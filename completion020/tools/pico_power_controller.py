"""MicroPython on Pico 2: GPIO15 controls EXTERNAL active-high load-switch EN.
Never connect GPIO15 to ESP32 power input. EN must accept 3.3 V logic and have
an external pull-down. At boot GPIO15 is high impedance until explicit ARM.
Protocol is serial text, JSON acknowledgements; not a calibrated trigger clock.
"""
import sys, select, time, json
from machine import Pin
pin = Pin(15, Pin.IN)
armed=False; scheduled=None
poll=select.poll();poll.register(sys.stdin,select.POLLIN)

def emit(event,**kw):
    kw.update(event=event,controller_ticks_ms=time.ticks_ms());print(json.dumps(kw))
emit('controller_boot',protocol='ids-power-v1',pin=15,armed=False)
while True:
    now=time.ticks_ms()
    if scheduled:
        off_at,on_at,phase=scheduled
        if phase=='waiting' and time.ticks_diff(now,off_at)>=0:
            pin.value(0);scheduled=(off_at,time.ticks_add(now,on_at),'off');emit('power_off')
        elif phase=='off' and time.ticks_diff(now,on_at)>=0:
            pin.value(1);scheduled=None;emit('power_on')
    if not poll.poll(2):continue
    line=sys.stdin.readline().strip(); parts=line.split()
    try:
        if parts==['ID']:emit('controller_id',protocol='ids-power-v1',pin=15,armed=armed)
        elif parts==['ARM','PHYSICAL'] and not scheduled:
            pin.init(Pin.OUT,value=1);armed=True;emit('armed',power_on=True)
        elif parts==['DISARM']:
            scheduled=None;armed=False;pin.init(Pin.IN);emit('disarmed',pin_high_impedance=True)
        elif not armed:emit('error',reason='not_armed')
        elif scheduled:emit('error',reason='cut_already_pending')
        elif parts==['ON']:pin.value(1);emit('power_on')
        elif parts==['OFF']:pin.value(0);emit('power_off')
        elif len(parts)==3 and parts[0]=='CUT':
            delay,duration=int(parts[1]),int(parts[2])
            if not 0<=delay<=5000 or not 1000<=duration<=10000:raise ValueError('bounds')
            scheduled=(time.ticks_add(time.ticks_ms(),delay),duration,'waiting')
            emit('cut_scheduled',delay_ms=delay,off_ms=duration)
        else:emit('error',reason='bad_command')
    except Exception as e:emit('error',reason=str(e))
