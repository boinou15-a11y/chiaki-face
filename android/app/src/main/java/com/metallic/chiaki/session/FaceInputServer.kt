// SPDX-License-Identifier: LicenseRef-AGPL-3.0-only-OpenSSL

package com.metallic.chiaki.session

import android.util.Base64
import android.util.Log
import com.metallic.chiaki.lib.ControllerState
import org.json.JSONArray
import org.json.JSONObject
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest

/**
 * Tiny dependency-free WebSocket server that receives controller state from the
 * face-tracking page, e.g. {"ls":[x,y],"rs":[x,y],"l2":0|1,"r2":0|1,"cross":0|1}.
 *
 * Sticks are -1..1 with up = negative Y (same as a real controller).
 * Clients must connect to ws://HOST:PORT/?key=KEY, otherwise they are rejected.
 * Only one client is active at a time; a new connection replaces the old one.
 *
 * Callbacks are invoked from background threads.
 */
class FaceInputServer(
	private val port: Int,
	private val key: String,
	private val onState: (ControllerState, Boolean) -> Unit, // state, whether it carries motion (roll) data
	private val onIdle: () -> Unit
)
{
	companion object
	{
		private const val TAG = "FaceInputServer"
		private const val WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
		private const val MAX_PAYLOAD = 65536
		private const val CLIENT_TIMEOUT_MS = 15000
	}

	private val lock = Any()
	private var serverSocket: ServerSocket? = null
	private var activeClient: Socket? = null
	@Volatile private var running = false

	fun start()
	{
		synchronized(lock)
		{
			if(running)
				return
			running = true
		}
		val thread = Thread { acceptLoop() }
		thread.isDaemon = true
		thread.start()
	}

	fun stop()
	{
		var server: ServerSocket? = null
		var client: Socket? = null
		synchronized(lock)
		{
			running = false
			server = serverSocket
			client = activeClient
			serverSocket = null
			activeClient = null
		}
		try { server?.close() } catch(e: IOException) {}
		try { client?.close() } catch(e: IOException) {}
	}

	private fun acceptLoop()
	{
		val server = try
		{
			val s = ServerSocket()
			s.reuseAddress = true
			s.bind(InetSocketAddress(port))
			s
		}
		catch(e: IOException)
		{
			Log.e(TAG, "Could not listen on port $port", e)
			synchronized(lock) { running = false }
			return
		}

		synchronized(lock)
		{
			if(!running)
			{
				try { server.close() } catch(e: IOException) {}
				return
			}
			serverSocket = server
		}

		while(running)
		{
			val client = try { server.accept() } catch(e: IOException) { break }
			var replaced: Socket? = null
			synchronized(lock)
			{
				replaced = activeClient
				activeClient = client
			}
			try { replaced?.close() } catch(e: IOException) {}
			val thread = Thread { handleClient(client) }
			thread.isDaemon = true
			thread.start()
		}
	}

	private fun handleClient(socket: Socket)
	{
		try
		{
			socket.tcpNoDelay = true
			socket.soTimeout = CLIENT_TIMEOUT_MS // the page streams constantly; drop silent clients
			val input = socket.getInputStream()
			val output = socket.getOutputStream()
			if(!handshake(input, output))
				return
			Log.i(TAG, "Face input client connected")
			readFrames(input, output)
		}
		catch(e: IOException)
		{
			// disconnect or timeout
		}
		catch(e: Exception)
		{
			Log.w(TAG, "Face input client error", e)
		}
		finally
		{
			try { socket.close() } catch(e: IOException) {}
			var wasActive = false
			synchronized(lock)
			{
				if(activeClient === socket)
				{
					activeClient = null
					wasActive = true
				}
			}
			if(wasActive)
			{
				Log.i(TAG, "Face input client disconnected")
				onIdle() // release everything so no button stays stuck
			}
		}
	}

	private fun readLine(input: InputStream): String?
	{
		val sb = StringBuilder()
		while(true)
		{
			val c = input.read()
			if(c < 0)
				return null
			if(c == 10) // \n
				break
			if(c != 13) // \r
				sb.append(c.toChar())
			if(sb.length > 4096)
				return null
		}
		return sb.toString()
	}

	private fun handshake(input: InputStream, output: OutputStream): Boolean
	{
		val requestLine = readLine(input) ?: return false
		var wsKey: String? = null
		var headerCount = 0
		while(true)
		{
			val line = readLine(input) ?: return false
			if(line.isEmpty())
				break
			if(++headerCount > 64)
				return false
			val idx = line.indexOf(':')
			if(idx > 0 && line.substring(0, idx).trim().equals("Sec-WebSocket-Key", ignoreCase = true))
				wsKey = line.substring(idx + 1).trim()
		}

		// request line looks like: GET /?key=1234 HTTP/1.1
		val parts = requestLine.split(" ")
		val path = if(parts.size >= 2) parts[1] else ""
		val authorized = Regex("[?&]key=" + Regex.escape(key) + "(&|$)").containsMatchIn(path)
		if(wsKey == null || !authorized)
		{
			output.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.US_ASCII))
			output.flush()
			return false
		}

		val digest = MessageDigest.getInstance("SHA-1").digest((wsKey + WS_GUID).toByteArray(Charsets.UTF_8))
		val accept = Base64.encodeToString(digest, Base64.NO_WRAP)
		val response = "HTTP/1.1 101 Switching Protocols\r\n" +
				"Upgrade: websocket\r\n" +
				"Connection: Upgrade\r\n" +
				"Sec-WebSocket-Accept: $accept\r\n\r\n"
		output.write(response.toByteArray(Charsets.US_ASCII))
		output.flush()
		return true
	}

	private fun InputStream.readByteOrThrow(): Int
	{
		val b = read()
		if(b < 0)
			throw EOFException()
		return b
	}

	private fun InputStream.readFully(buf: ByteArray)
	{
		var offset = 0
		while(offset < buf.size)
		{
			val n = read(buf, offset, buf.size - offset)
			if(n < 0)
				throw EOFException()
			offset += n
		}
	}

	private fun readFrames(input: InputStream, output: OutputStream)
	{
		while(running)
		{
			val b0 = input.readByteOrThrow()
			val b1 = input.readByteOrThrow()
			val opcode = b0 and 0x0F
			val masked = (b1 and 0x80) != 0
			var length = (b1 and 0x7F).toLong()
			if(length == 126L)
			{
				length = ((input.readByteOrThrow() shl 8) or input.readByteOrThrow()).toLong()
			}
			else if(length == 127L)
			{
				length = 0L
				for(i in 0 until 8)
					length = (length shl 8) or input.readByteOrThrow().toLong()
			}
			if(length < 0 || length > MAX_PAYLOAD)
				return

			val mask = ByteArray(4)
			if(masked)
				input.readFully(mask)
			val payload = ByteArray(length.toInt())
			input.readFully(payload)
			if(masked)
			{
				for(i in payload.indices)
					payload[i] = (payload[i].toInt() xor mask[i % 4].toInt()).toByte()
			}

			when(opcode)
			{
				0x1 -> handleText(String(payload, Charsets.UTF_8))
				0x8 -> return // close
				0x9 -> sendFrame(output, 0xA, payload) // ping -> pong
				else -> {}
			}
		}
	}

	private fun sendFrame(output: OutputStream, opcode: Int, payload: ByteArray)
	{
		if(payload.size > 125)
			return
		output.write(0x80 or opcode)
		output.write(payload.size)
		output.write(payload)
		output.flush()
	}

	private fun axis(array: JSONArray?, index: Int): Short
	{
		val v = (array?.optDouble(index, 0.0) ?: 0.0).coerceIn(-1.0, 1.0)
		return (v * 32767.0).toInt().toShort()
	}

	private fun trigger(o: JSONObject, name: String): UByte
	{
		val v = o.optDouble(name, 0.0).coerceIn(0.0, 1.0)
		return (v * 255.0).toInt().toUByte()
	}

	private fun handleText(text: String)
	{
		val o = try { JSONObject(text) } catch(e: Exception) { return }
		val ls = o.optJSONArray("ls")
		val rs = o.optJSONArray("rs")
		var buttons = 0U
		if(o.optDouble("cross", 0.0) > 0.5)
			buttons = buttons or ControllerState.BUTTON_CROSS
		if(o.optDouble("square", 0.0) > 0.5)
			buttons = buttons or ControllerState.BUTTON_BOX
		if(o.optDouble("triangle", 0.0) > 0.5)
			buttons = buttons or ControllerState.BUTTON_PYRAMID
		val state = ControllerState(
			buttons = buttons,
			l2State = trigger(o, "l2"),
			r2State = trigger(o, "r2"),
			leftX = axis(ls, 0),
			leftY = axis(ls, 1),
			rightX = axis(rs, 0),
			rightY = axis(rs, 1)
		)

		// "roll" is the controller tilt in degrees (positive = tilted right). It is turned into
		// fake motion data: gravity direction plus an orientation rotated about the forward axis.
		val hasMotion = o.has("roll")
		if(hasMotion)
		{
			val rad = Math.toRadians(o.optDouble("roll", 0.0).coerceIn(-90.0, 90.0))
			state.accelX = (-Math.sin(rad)).toFloat()
			state.accelY = Math.cos(rad).toFloat()
			state.accelZ = 0.0f
			state.gyroX = 0.0f
			state.gyroY = 0.0f
			state.gyroZ = 0.0f
			state.orientX = 0.0f
			state.orientY = 0.0f
			state.orientZ = Math.sin(-rad / 2.0).toFloat()
			state.orientW = Math.cos(rad / 2.0).toFloat()
		}
		onState(state, hasMotion)
	}
}
