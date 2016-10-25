/* libUIOHook: Cross-platfrom userland keyboard and mouse hooking.
 * Copyright (C) 2006-2016 Alexander Barker.  All Rights Received.
 * https://github.com/kwhat/libuiohook/
 *
 * libUIOHook is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * libUIOHook is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define USE_XKB 1

#include <inttypes.h>
#include <limits.h>
#include <X11/extensions/XInput2.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/time.h>
#include <uiohook.h>
#ifdef USE_XKB
#include <X11/XKBlib.h>
#endif
#include <X11/keysym.h>
#include <X11/Xlibint.h>
#include <X11/Xlib.h>
#include <X11/extensions/record.h>
#if defined(USE_XINERAMA) && !defined(USE_XRANDR)
#include <X11/extensions/Xinerama.h>
#elif defined(USE_XRANDR)
#include <X11/extensions/Xrandr.h>
#else
// TODO We may need to fallback to the xf86vm extension for things like TwinView.
#pragma message("*** Warning: Xinerama or XRandR support is required to produce cross-platform mouse coordinates for multi-head configurations!")
#pragma message("... Assuming single-head display.")
#endif

#include <libudev.h>

#include "logger.h"
#include "input_helper.h"

// Thread and hook handles.
static bool running;

static pthread_cond_t hook_xrecord_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t hook_xrecord_mutex = PTHREAD_MUTEX_INITIALIZER;

Display *display;

// Modifiers for tracking key masks.
static uint16_t current_modifiers = 0x0000;

// Virtual event pointer.
static uiohook_event event;

// Event dispatch callback.
static dispatcher_t dispatcher = NULL;

UIOHOOK_API void hook_set_dispatch_proc(dispatcher_t dispatch_proc) {
	logger(LOG_LEVEL_DEBUG, "%s [%u]: Setting new dispatch callback to %#p.\n",
	__FUNCTION__, __LINE__, dispatch_proc);

	dispatcher = dispatch_proc;
}

// Send out an event if a dispatcher was set.
static inline void dispatch_event(uiohook_event * const event) {
	if (dispatcher != NULL) {
		logger(LOG_LEVEL_DEBUG, "%s [%u]: Dispatching event type %u.\n",
		__FUNCTION__, __LINE__, event->type);

		dispatcher(event);
	} else {
		logger(LOG_LEVEL_WARN, "%s [%u]: No dispatch callback set!\n",
		__FUNCTION__, __LINE__);
	}
}

// Set the native modifier mask for future events.
static inline void set_modifier_mask(uint16_t mask) {
	current_modifiers |= mask;
}

// Unset the native modifier mask for future events.
static inline void unset_modifier_mask(uint16_t mask) {
	current_modifiers ^= mask;
}

// Get the current native modifier mask state.
static inline uint16_t get_modifiers() {
	return current_modifiers;
}

// Initialize the modifier mask to the current modifiers.
static void initialize_modifiers() {
	current_modifiers = 0x0000;

	KeyCode keycode;
	char keymap[32];
	XQueryKeymap(display, keymap);

	Window unused_win;
	int unused_int;
	unsigned int mask;
	if (XQueryPointer(display, DefaultRootWindow(display), &unused_win,
			&unused_win, &unused_int, &unused_int, &unused_int, &unused_int,
			&mask)) {
		if (mask & ShiftMask) {
			keycode = XKeysymToKeycode(display, XK_Shift_L);
			if (keymap[keycode / 8] & (1 << (keycode % 8))) {
				set_modifier_mask(MASK_SHIFT_L);
			}
			keycode = XKeysymToKeycode(display, XK_Shift_R);
			if (keymap[keycode / 8] & (1 << (keycode % 8))) {
				set_modifier_mask(MASK_SHIFT_R);
			}
		}
		if (mask & ControlMask) {
			keycode = XKeysymToKeycode(display, XK_Control_L);
			if (keymap[keycode / 8] & (1 << (keycode % 8))) {
				set_modifier_mask(MASK_CTRL_L);
			}
			keycode = XKeysymToKeycode(display, XK_Control_R);
			if (keymap[keycode / 8] & (1 << (keycode % 8))) {
				set_modifier_mask(MASK_CTRL_R);
			}
		}
		if (mask & Mod1Mask) {
			keycode = XKeysymToKeycode(display, XK_Alt_L);
			if (keymap[keycode / 8] & (1 << (keycode % 8))) {
				set_modifier_mask(MASK_ALT_L);
			}
			keycode = XKeysymToKeycode(display, XK_Alt_R);
			if (keymap[keycode / 8] & (1 << (keycode % 8))) {
				set_modifier_mask(MASK_ALT_R);
			}
		}
		if (mask & Mod4Mask) {
			keycode = XKeysymToKeycode(display, XK_Super_L);
			if (keymap[keycode / 8] & (1 << (keycode % 8))) {
				set_modifier_mask(MASK_META_L);
			}
			keycode = XKeysymToKeycode(display, XK_Super_R);
			if (keymap[keycode / 8] & (1 << (keycode % 8))) {
				set_modifier_mask(MASK_META_R);
			}
		}

		if (mask & Button1Mask) {
			set_modifier_mask(MASK_BUTTON1);
		}
		if (mask & Button2Mask) {
			set_modifier_mask(MASK_BUTTON2);
		}
		if (mask & Button3Mask) {
			set_modifier_mask(MASK_BUTTON3);
		}
		if (mask & Button4Mask) {
			set_modifier_mask(MASK_BUTTON4);
		}
		if (mask & Button5Mask) {
			set_modifier_mask(MASK_BUTTON5);
		}
	} else {
		logger(LOG_LEVEL_WARN,
				"%s [%u]: XQueryPointer failed to get current modifiers!\n",
				__FUNCTION__, __LINE__);

		keycode = XKeysymToKeycode(display, XK_Shift_L);
		if (keymap[keycode / 8] & (1 << (keycode % 8))) {
			set_modifier_mask(MASK_SHIFT_L);
		}
		keycode = XKeysymToKeycode(display, XK_Shift_R);
		if (keymap[keycode / 8] & (1 << (keycode % 8))) {
			set_modifier_mask(MASK_SHIFT_R);
		}
		keycode = XKeysymToKeycode(display, XK_Control_L);
		if (keymap[keycode / 8] & (1 << (keycode % 8))) {
			set_modifier_mask(MASK_CTRL_L);
		}
		keycode = XKeysymToKeycode(display, XK_Control_R);
		if (keymap[keycode / 8] & (1 << (keycode % 8))) {
			set_modifier_mask(MASK_CTRL_R);
		}
		keycode = XKeysymToKeycode(display, XK_Alt_L);
		if (keymap[keycode / 8] & (1 << (keycode % 8))) {
			set_modifier_mask(MASK_ALT_L);
		}
		keycode = XKeysymToKeycode(display, XK_Alt_R);
		if (keymap[keycode / 8] & (1 << (keycode % 8))) {
			set_modifier_mask(MASK_ALT_R);
		}
		keycode = XKeysymToKeycode(display, XK_Super_L);
		if (keymap[keycode / 8] & (1 << (keycode % 8))) {
			set_modifier_mask(MASK_META_L);
		}
		keycode = XKeysymToKeycode(display, XK_Super_R);
		if (keymap[keycode / 8] & (1 << (keycode % 8))) {
			set_modifier_mask(MASK_META_R);
		}

		keycode = XKeysymToKeycode(display, XK_Super_R);
		if (keymap[keycode / 8] & (1 << (keycode % 8))) {
			set_modifier_mask(MASK_META_R);
		}
	}
}

void set_modifiers_mask(unsigned short int scancode) {
	switch (scancode) {
	case VC_SHIFT_L:
		set_modifier_mask(MASK_SHIFT_L);
		break;

	case VC_SHIFT_R:
		set_modifier_mask(MASK_SHIFT_R);
		break;

	case VC_CONTROL_L:
		set_modifier_mask(MASK_CTRL_L);
		break;

	case VC_CONTROL_R:
		set_modifier_mask(MASK_CTRL_R);
		break;

	case VC_ALT_L:
		set_modifier_mask(MASK_ALT_L);
		break;

	case VC_ALT_R:
		set_modifier_mask(MASK_ALT_R);
		break;

	case VC_META_L:
		set_modifier_mask(MASK_META_L);
		break;

	case VC_META_R:
		set_modifier_mask(MASK_META_R);
		break;
	}
}

void unset_modifiers_mask(unsigned short int scancode) {
	switch (scancode) {
	case VC_SHIFT_L:
		if (get_modifiers() & MASK_SHIFT_L) {
			unset_modifier_mask(MASK_SHIFT_L);
		}
		break;

	case VC_SHIFT_R:
		if (get_modifiers() & MASK_SHIFT_R) {
			unset_modifier_mask(MASK_SHIFT_R);
		}
		break;

	case VC_CONTROL_L:
		if (get_modifiers() & MASK_CTRL_L) {
			unset_modifier_mask(MASK_CTRL_L);
		}
		break;

	case VC_CONTROL_R:
		if (get_modifiers() & MASK_CTRL_R) {
			unset_modifier_mask(MASK_CTRL_R);
		}
		break;

	case VC_ALT_L:
		if (get_modifiers() & MASK_ALT_L) {
			unset_modifier_mask(MASK_ALT_L);
		}
		break;

	case VC_ALT_R:
		if (get_modifiers() & MASK_ALT_R) {
			unset_modifier_mask(MASK_ALT_R);
		}
		break;

	case VC_META_L:
		if (get_modifiers() & MASK_META_L) {
			unset_modifier_mask(MASK_META_L);
		}
		break;

	case VC_META_R:
		if (get_modifiers() & MASK_META_R) {
			unset_modifier_mask(MASK_META_R);
		}
		break;
	}
}

const char *getLastPathComponent(const char *path) {
	char *result = 0;
	char *p = malloc(strlen(path));
	strcpy(p, path);
	p = strtok(p, "/");
	do {
		p = strtok('\0', "/");
		if (p) {
			result = p;
		}
	} while (p);
	free(p);
	return result;
}

char **getKeyboards(int *namesLen) {
	struct udev_list_entry *devices, *dev_list_entry;
	struct udev *udev = udev_new();

	char **names = malloc(sizeof(char));
	if (!udev) {
		exit(1);
	}

	struct udev_enumerate *enumerate = udev_enumerate_new(udev);
	udev_enumerate_add_match_subsystem(enumerate, "input");
	udev_enumerate_add_match_property(enumerate, "ID_INPUT_KEYBOARD", "1");
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);
	int i = 0;
	udev_list_entry_foreach(dev_list_entry, devices)
	{
		const char *path = udev_list_entry_get_name(dev_list_entry);
		struct udev_device *dev = udev_device_new_from_syspath(udev, path);

		const char *p = udev_device_get_devnode(dev);
		if (p) {
			const char *a = getLastPathComponent(p);
			size_t len = strlen(a);
			names = realloc(names, (i + 1) * sizeof(char));
			names[i] = malloc(len * sizeof(char));
			memcpy(names[i], a, len * sizeof(char));
			i++;
		}
		udev_device_unref(dev);
	}

	udev_enumerate_unref(enumerate);
	udev_unref(udev);
	*namesLen = i;
	return names;
}

void freeListArr(char **list, int len) {
	for (int i = 0; i < len; i++) {
		free(list[i]);
	}
	free(list);
}

int contains(char **list, int len, const char *name) {
	for (int i = 0; i < len; i++) {
		if (strcmp(list[i], name) == 0) {
			return 1;
		}
	}
	return 0;
}

void process_event(XIRawEvent *rawEvent) {
	unsigned short int scancode = keycode_to_scancode(rawEvent->detail);
	if (rawEvent->evtype == XI_RawKeyPress) {
		event.type = EVENT_KEY_PRESSED;
		set_modifiers_mask(scancode);
	} else if (rawEvent->evtype == XI_RawKeyRelease) {
		event.type = EVENT_KEY_RELEASED;
		unset_modifiers_mask(scancode);
	}
	event.mask = get_modifiers();

	KeyCode keyCode = scancode_to_keycode(scancode);

	XkbStateRec state;
	if (XkbGetState(rawEvent->display, rawEvent->deviceid, &state) == 0) {
		KeySym keysym = XkbKeycodeToKeysym(rawEvent->display, keyCode,
				state.group, state.mods);

		event.time = rawEvent->time;
		event.reserved = 0x00;

		event.data.keyboard.keycode = scancode;
		event.data.keyboard.rawcode = keysym;

		int n;
		XIDeviceInfo *info = XIQueryDevice(rawEvent->display,
				rawEvent->deviceid, &n);
		if (info) {
			event.data.keyboard.keyboardName = info->name;
		} else {
			event.data.keyboard.keyboardName = 0x00;
		}

		// Fire key pressed event.
		dispatch_event(&event);

		if ((event.reserved ^ 0x01) && (rawEvent->evtype != XI_RawKeyRelease)) {
			wchar_t buffer[1];

			// Check to make sure the key is printable.
			size_t count = keysym_to_unicode(keysym, buffer, sizeof(buffer));
			if (count > 0) {
				event.time = rawEvent->time;
				event.reserved = 0x00;

				event.type = EVENT_KEY_TYPED;
				event.mask = get_modifiers();

				event.data.keyboard.keycode = VC_UNDEFINED;
				event.data.keyboard.rawcode = keysym;
				event.data.keyboard.keychar = buffer[0];

				logger(LOG_LEVEL_INFO, "%s [%u]: Key %#X typed. (%lc)\n",
				__FUNCTION__, __LINE__, event.data.keyboard.keycode,
						(wint_t) event.data.keyboard.keychar);

				// Fire key typed event.
				dispatch_event(&event);
			}
		}

		if (info) {
			XIFreeDeviceInfo(info);
		}
	}
}

char *getDeviceNode(int deviceid) {
	int nprops;
	char *result = 0x00;
	Atom *props = XIListProperties(display, deviceid, &nprops);
	while (nprops--) {
		Atom act_type;
		int act_format;
		unsigned long nitems, bytes_after;
		unsigned char *data;
		char *name = XGetAtomName(display, props[nprops]);
		if ((strcmp(name, "Device Node") == 0)
				&& (XIGetProperty(display, deviceid, props[nprops], 0,
						1000, False, AnyPropertyType, &act_type, &act_format,
						&nitems, &bytes_after, &data) == Success)
				&& (act_format == 8)) {
			result = (char *) data;
		}
		XFree(name);
	}
	XFree(props);
	return result;
}

UIOHOOK_API int hook_run() {
	int status = UIOHOOK_SUCCESS;

	// Open the control display for XRecord.
	display = XOpenDisplay(NULL);

	// Open a data display for XRecord.
	// NOTE This display must be opened on the same thread as XRecord.
	if (display != NULL) {
		logger(LOG_LEVEL_DEBUG, "%s [%u]: XOpenDisplay successful.\n",
		__FUNCTION__, __LINE__);

		// Initialize starting modifiers.
		initialize_modifiers();

		int ndevices, xi_opcode, evt, error, namesLen;
		if (!XQueryExtension(display, "XInputExtension", &xi_opcode, &evt,
				&error)) {
			logger(LOG_LEVEL_ERROR,
					"%s [%u]: X Input extension not available.\n",
					__FUNCTION__, __LINE__);
			exit(-1);
		}

		char **names = getKeyboards(&namesLen);
		int j = 0;
		XIEventMask *masks = malloc(1);
		XIDeviceInfo *info = XIQueryDevice(display, XIAllDevices, &ndevices);
		for (int i = 0; i < ndevices; i++) {
			XIDeviceInfo *dev = &info[i];
			if ((dev->use == XIMasterKeyboard)
					|| (dev->use == XISlaveKeyboard)) {
				char *devnode = getDeviceNode(dev->deviceid);
				if (devnode && contains(names, namesLen, getLastPathComponent(devnode))) {
					XIEventMask m;
					m.deviceid = dev->deviceid;
					m.mask_len = XIMaskLen(XI_LASTEVENT);
					m.mask = calloc(m.mask_len, sizeof(char));
					XISetMask(m.mask, XI_RawKeyPress);
					XISetMask(m.mask, XI_RawKeyRelease);

					j++;
					masks = realloc(masks, j * sizeof(m));
					masks[j - 1] = m;
				}
			}
		}
		XIFreeDeviceInfo(info);
		freeListArr(names, namesLen);

		Window win = DefaultRootWindow(display);
		XISelectEvents(display, win, masks, j);

		int timesleep = 100;
		pthread_mutex_lock(&hook_xrecord_mutex);
		running = true;

		while (running) {
			pthread_mutex_unlock(&hook_xrecord_mutex);

			XEvent ev;
			XGenericEventCookie *cookie = (XGenericEventCookie*) &ev.xcookie;
			XNextEvent(display, (XEvent*) &ev);
			if (XGetEventData(display, cookie) && (cookie->type == GenericEvent)
					&& (cookie->extension == xi_opcode)) {
				switch (cookie->evtype) {
				case XI_RawKeyPress:
				case XI_RawKeyRelease: {
					process_event(cookie->data);
					break;
				}
				}
			}

			struct timeval tv;
			gettimeofday(&tv, NULL);

			struct timespec ts;
			ts.tv_sec = time(NULL) + timesleep / 1000;
			ts.tv_nsec = tv.tv_usec * 1000 + 1000 * 1000 * (timesleep % 1000);
			ts.tv_sec += ts.tv_nsec / (1000 * 1000 * 1000);
			ts.tv_nsec %= (1000 * 1000 * 1000);

			pthread_mutex_lock(&hook_xrecord_mutex);
			pthread_cond_timedwait(&hook_xrecord_cond, &hook_xrecord_mutex,
					&ts);
			XFreeEventData(display, cookie);
		}

		// Unlock after loop exit.
		pthread_mutex_unlock(&hook_xrecord_mutex);

		// Set the exit status.
		status = UIOHOOK_SUCCESS;

		XDestroyWindow(display, win);

		for (int i = 0; i < j; i++) {
			XIEventMask *m = &masks[i];
			free(m->mask);
		}
		free(masks);

		// Close down open display.
		if (display) {
			XCloseDisplay(display);
		}
	} else {
		logger(LOG_LEVEL_ERROR, "%s [%u]: XOpenDisplay failure!\n",
		__FUNCTION__, __LINE__);

		// Set the exit status.
		status = UIOHOOK_ERROR_X_OPEN_DISPLAY;
	}

	logger(LOG_LEVEL_DEBUG,
			"%s [%u]: Something, something, something, complete.\n",
			__FUNCTION__, __LINE__);

	return status;
}

UIOHOOK_API int hook_stop() {
	int status = UIOHOOK_FAILURE;

	if ((display != NULL) && running) {
		pthread_mutex_lock(&hook_xrecord_mutex);
		running = false;
		pthread_cond_signal(&hook_xrecord_cond);
		pthread_mutex_unlock(&hook_xrecord_mutex);
		status = UIOHOOK_SUCCESS;
	}

	logger(LOG_LEVEL_DEBUG, "%s [%u]: Status: %#X.\n",
	__FUNCTION__, __LINE__, status);

	return status;
}
