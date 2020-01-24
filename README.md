# BlueGate
PoC for the Remote Desktop Gateway vulnerability - CVE-2020-0609 &amp; CVE-2020-0610. Thanks to [ollypwn](https://twitter.com/ollypwn) for pointing out my silly mistake!

## Setup
I'm using a patched version of `pydtls` as the original repository wouldn't build properly.
```
cd pydtls
sudo python setup.py install
```

## Denial of Service
A PoC for the DoS attack can be found in [dos.py](https://github.com/ioncodes/BlueGate/blob/master/dos.py). This essentially crashes the Remote Desktop Gateway service. Initial PoC can be found [here](https://github.com/ioncodes/BlueGate/blob/91ad3951c0db0944a5f8ade8c4af1ae6bd69836e/dos.py).

### Usage
```
python dos.py 192.168.8.133 3391
```

### Result
Before:
![before](https://github.com/ioncodes/BlueGate/blob/master/images/before_dos.png?raw=true)

After:
![after](https://github.com/ioncodes/BlueGate/blob/master/images/after_dos.png?raw=true)
