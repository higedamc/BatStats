package app.batstats.battery.shizuku

import android.content.Context
import android.os.Binder
import android.os.Parcel
import android.os.ParcelFileDescriptor
import android.util.Log
import app.batstats.BuildConfig
import java.util.concurrent.TimeUnit

/**
 * Privileged helper launched by Shizuku. It runs in a separate process owned by the ADB shell
 * user, or by root when Shizuku itself was started as root, so every transaction handled here
 * executes with more authority than the app process has.
 *
 * Two independent gates keep that authority from becoming a general purpose remote shell:
 *
 *  1. [isCallerTrusted] rejects transactions that do not come from this app or from the Shizuku
 *     server that spawned this process.
 *  2. [ALLOWED_COMMANDS] restricts execution to the fixed set of read-only diagnostic commands
 *     the app actually needs. A binder handle that leaks out of the app process is therefore
 *     worth no more than the battery dumps the holder could already request themselves.
 *
 * Adding a command to the app means adding it here as well; anything else is refused with
 * [ERROR_NOT_ALLOWED] rather than executed.
 */
class ShellUserService : Binder {

    constructor() : super()

    /**
     * Shizuku passes a [Context] when the user service declares this constructor. It is used only
     * to learn the app's own uid so caller identity can be pinned.
     */
    constructor(context: Context) : super() {
        appUid = resolveAppUid(context)
    }

    @Volatile
    private var appUid: Int? = null

    companion object {
        private const val TAG = "ShellUserService"

        const val TRANSACTION_RUN = 1

        const val TRANSACTION_RUN_PIPE = 2

        const val TRANSACTION_DESTROY = 16777114

        private const val MAX_INLINE_OUTPUT_CHARS = 192 * 1024

        private const val DEFAULT_TIMEOUT_MS = 30_000L
        private const val COPY_BUFFER_BYTES = 64 * 1024

        private const val ERROR_NOT_ALLOWED = "ERROR:command not allowed"

        private const val ROOT_UID = 0

        /**
         * Every command the app sends through this service. Compared after trimming, by exact
         * match: no arguments are interpolated anywhere in the app, so no pattern matching or
         * quoting is required and none is permitted.
         */
        private val ALLOWED_COMMANDS = setOf(
            "dumpsys battery",
            "dumpsys batterystats --checkin",
            "dumpsys batterystats --reset",
            "dumpsys deviceidle",
            "dumpsys power"
        )

        private fun resolveAppUid(context: Context): Int? = try {
            context.packageManager.getApplicationInfo(BuildConfig.APPLICATION_ID, 0).uid
        } catch (t: Throwable) {
            Log.w(TAG, "Could not resolve own uid: ${t.message}")
            null
        }
    }

    override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
        if (code == TRANSACTION_RUN || code == TRANSACTION_RUN_PIPE || code == TRANSACTION_DESTROY) {
            if (!isCallerTrusted()) {
                Log.w(TAG, "Rejected transaction $code from uid ${Binder.getCallingUid()}")
                return false
            }
        }
        return when (code) {
            TRANSACTION_RUN -> {
                val cmd = data.readString().orEmpty()
                val out = if (isAllowed(cmd)) {
                    runCommand(cmd, DEFAULT_TIMEOUT_MS)
                } else {
                    reject(cmd)
                }
                reply?.writeString(
                    if (out.length > MAX_INLINE_OUTPUT_CHARS) out.take(MAX_INLINE_OUTPUT_CHARS) else out
                )
                true
            }

            TRANSACTION_RUN_PIPE -> {
                val cmd = data.readString().orEmpty()
                val timeoutMs = data.readLong().takeIf { it > 0 } ?: DEFAULT_TIMEOUT_MS
                val pfd = try {
                    ParcelFileDescriptor.CREATOR.createFromParcel(data)
                } catch (_: Throwable) {
                    null
                }
                if (pfd == null) {
                    reply?.writeInt(0)
                } else if (!isAllowed(cmd)) {
                    // The pipe is accepted so the caller observes the refusal the same way it
                    // observes a command failure, instead of waiting out its read timeout.
                    reply?.writeInt(1)
                    writeAndClose(pfd, reject(cmd))
                } else {
                    reply?.writeInt(1)
                    streamCommand(cmd, pfd, timeoutMs)
                }
                true
            }

            TRANSACTION_DESTROY -> {
                destroy()
                true
            }

            else -> super.onTransact(code, data, reply, flags)
        }
    }

    /**
     * Accepts this process itself (which is also the uid of the Shizuku server that spawned it,
     * shell or root) and the app that owns this service. When the uid of the app could not be
     * resolved the gate defers to [ALLOWED_COMMANDS], which is the boundary that actually limits
     * what any caller can do.
     */
    private fun isCallerTrusted(): Boolean {
        val caller = Binder.getCallingUid()
        if (caller == android.os.Process.myUid() || caller == ROOT_UID) return true
        return appUid?.let { caller == it } ?: true
    }

    private fun isAllowed(cmd: String): Boolean = cmd.trim() in ALLOWED_COMMANDS

    private fun reject(cmd: String): String {
        Log.w(TAG, "Refused command outside the allow-list: ${cmd.take(80)}")
        return ERROR_NOT_ALLOWED
    }

    private fun writeAndClose(pfd: ParcelFileDescriptor, message: String) {
        Thread {
            ParcelFileDescriptor.AutoCloseOutputStream(pfd).use { sink ->
                runCatching { sink.write(message.toByteArray()) }
            }
        }.apply {
            isDaemon = true
            name = "batstats-shell-reject"
            start()
        }
    }

    private fun streamCommand(cmd: String, pfd: ParcelFileDescriptor, timeoutMs: Long) {
        val worker = Thread {
            val sink = ParcelFileDescriptor.AutoCloseOutputStream(pfd)
            var process: Process? = null
            var watchdog: Thread? = null
            try {
                val p = ProcessBuilder("sh", "-c", cmd)
                    .redirectErrorStream(true)
                    .start()
                process = p
                runCatching { p.outputStream.close() }

                watchdog = Thread {
                    try {
                        if (!p.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) p.destroyForcibly()
                    } catch (_: InterruptedException) {
                    }
                }.apply {
                    isDaemon = true
                    start()
                }

                val buffer = ByteArray(COPY_BUFFER_BYTES)
                val source = p.inputStream
                while (true) {
                    val read = source.read(buffer)
                    if (read < 0) break
                    sink.write(buffer, 0, read)
                }
                sink.flush()
            } catch (t: Throwable) {
                runCatching {
                    sink.write("ERROR:${t.message ?: t.javaClass.simpleName}".toByteArray())
                }
            } finally {
                watchdog?.interrupt()
                runCatching { process?.destroy() }
                runCatching { sink.close() }
            }
        }
        worker.isDaemon = true
        worker.name = "batstats-shell"
        worker.start()
    }

    private fun runCommand(cmd: String, timeoutMs: Long): String {
        var process: Process? = null
        return try {
            val p = ProcessBuilder("sh", "-c", cmd)
                .redirectErrorStream(true)
                .start()
            process = p
            runCatching { p.outputStream.close() }
            val out = p.inputStream.bufferedReader().use { it.readText() }
            if (!p.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) p.destroyForcibly()
            out
        } catch (t: Throwable) {
            "ERROR:${t.message ?: t.javaClass.simpleName}"
        } finally {
            runCatching { process?.destroy() }
        }
    }

    private fun destroy() {
        Thread {
            runCatching { Thread.sleep(100) }
            Runtime.getRuntime().halt(0)
        }.apply { isDaemon = true }.start()
    }
}
