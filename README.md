# CS-GY 6803 Individual Final

Information Systems Security Engineering and Management (ISSEM) with Raj Rajagopalan at NYU, Summer 2026

- [Matthew Bentz](mailto:mb9661@nyu.edu)

## Project Spec

- [ISSEM Final Project summer 2026.pdf](ISSEM%20Final%20Project%20summer%202026.pdf)

## References

- [Infant-Incubator-Simulator](https://github.com/rajan0112/Infant-Incubator-Simulator)
- A copy of the relevant lab 3/4 source files is provided under [reference](./reference/).

## Layout

- [src/infinc.py](./src/infinc.py)
    - Defines:
        - `SimpleThermometer`
        - `SimpleHeatGenerator`
        - `Human`
        - `SmartThermometer`
        - `SmartHeater`
        - `Incubator`
        - `Simulator`
    - Simulator is the daemon thread that takes in parameters, such as the infant, incubator, temperature, and timing configuration.
    - Each time step calculates and updates the temperature of the infant, incubator, and room. After calculation, the energy is added to the incubator.
- [src/SampleClient.py](./src/SampleClient.py)
    - Defines:
        - `SimpleClient`
    - Runs a SimpleClient instance with local/direct resources for the simulator, such as SmartThermometer and SmartHeater.
    - Update infant/incubator temperature methods get data from the local resources and update the matplot figure.
- [src/SampleNetworkClient.py](./src/SampleNetworkClient.py)
    - Defines:
        - `SimpleNetworkClient`
    - Runs a SimpleNetworkClient instance, which authenticates with and gets temperature from the server through UDP ports. 
    - Update infant/incubator temperature methods get data from the remote server and update the matplot figure.
- [src/SampleNetworkServer.py](./src/SampleNetworkServer.py)
    - Defines:
        - `SmartNetworkThermometer`
        - `SimpleClient` (redundant)
    - Runs two SmartNetworkThermometer daemon processes on ports 23456 (infant thermometer) and 23457 (incubator thermometer). 
    - Along with the simulator, and instance off SimpleClient is created, duplicated from SampleClient.py.

## Usage

Setup a Python venv and install the required packages.

```bash
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip3 install -r requirements.txt
```

Set the password env var and run the sample network server. This will create a matplot frame from SampleClient and start the server listening on port 23456 for the infant thermometer and port 23457 for the incubator thermometer.

```bash
$ export AUTH_PASSWORD="your-password"
$ python3 src/SampleNetworkServer.py
```