# BlueGate
PoC for the Remote Desktop Gateway vulnerability - CVE-2020-0609 &amp; CVE-2020-0610. Thanks to [ollypwn](https://twitter.com/ollypwn) for pointing out my silly mistake!

## Denial of Service
A PoC for the DoS attack can be found in [dos.py](https://github.com/ioncodes/BlueGate/blob/master/dos.py). You can use it as follows:  

### Setup
```
cd pydtls
sudo python setup.py install
```

### Usage
```
python dos.py 192.168.8.133 3391
```

### Result
Before:

After:
