package com.aetnagroup.mydesk

import android.content.Context
import com.aetnagroup.mydesk.accessibility.MyDeskAccessibilityService
import com.aetnagroup.mydesk.storage.DeviceConfig
import com.aetnagroup.mydesk.storage.DeviceConfigStore

/** Main-thread state shared by the service and lifecycle-bound UI listeners. */
object AgentController {
    enum class State { UNPAIRED, ACCESSIBILITY_DISABLED, CONNECTING, ONLINE, ACTIVE, RECONNECTING, PAUSED, INVALID }
    var state = State.UNPAIRED
        private set
    private val listeners = mutableSetOf<(State) -> Unit>()
    private var service: MyDeskAccessibilityService? = null
    fun observe(listener: (State) -> Unit) { listeners.add(listener); listener(state) }
    fun remove(listener: (State) -> Unit) { listeners.remove(listener) }
    fun publish(value: State) { state = value; listeners.toList().forEach { it(value) } }
    fun attach(value: MyDeskAccessibilityService) { service = value; refresh(value) }
    fun detach(value: MyDeskAccessibilityService) { if (service === value) { service = null; refresh(value) } }
    fun refresh(context: Context) {
        val store = DeviceConfigStore(context)
        val config = store.load()
        when {
            store.corrupt || store.invalid -> publish(State.INVALID)
            config == null -> publish(State.UNPAIRED)
            store.paused -> publish(State.PAUSED)
            service == null -> publish(State.ACCESSIBILITY_DISABLED)
            else -> service?.applyConfiguration()
        }
    }
    fun pair(context: Context, config: DeviceConfig) {
        service?.stopControl("new_pairing")
        DeviceConfigStore(context).save(config)
        refresh(context)
    }
    fun pause(context: Context) {
        val store = DeviceConfigStore(context)
        store.paused = !store.paused
        if (store.paused) service?.stopControl("local_paused")
        refresh(context)
    }
    fun clear(context: Context) {
        service?.stopControl("local_removed")
        DeviceConfigStore(context).clear()
        refresh(context)
    }
}
