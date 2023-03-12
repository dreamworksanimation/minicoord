To run minicoord you'll need *tornado-5.1.1* and *requests*.

```bash
rez-env tornado-5.1.1 requests
git clone https://github.anim.dreamworks.com/OpenMoonRay/minicoord.git
cd minicoord/minicoord
python -i run.py
```

Should display

```bash
INFO:run:Starting coordinator service on port 8888
```

and leave you in the Python interpreter.

To start a node run

```bash
arras4_node --coordinator-host localhost --coordinator-port 8888 -l 5
```

To run without Consul, use the cmake_linux branch of arras4_node and add the argument "--no-consul"

To run without rez, "packaging_system" in the session definition should be set to "current-environment"

