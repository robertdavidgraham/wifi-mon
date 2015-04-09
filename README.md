wifi-mon
========

This is a web-based WiFi monitor. It's output is similar to `airocrack-ng`,
except that instead of on the command-line, you access this via a web-page.
This allows you to drill down into things with clicks/touches within the
web browser.

# BUILDING

The prerequisite is the libpcap library, or WinPcap on Windows. The Windows
version doesn't support "monitor mode" so won't do much, unless you are
using the "Airpcap" adapters.

    $ apt-get install libcap-dev
    
To build on Linux and Mac, just type `make`. This may work under msys/cygwin
as well.

    $ make
    $ make test

On Mac, you can probably also build this with XCode using the included
project in the `xcode4` subdirectory. On Windows, you can probably build 
using the project in the `vs10` subdirectory.

I haven't built for any other platforms.


# HOW TO RUN

This is a web-application. Building the app puts a binary in the `bin`
directory, but you actually want to run it from the `www` directory:

    $ make
    $ cd www
    $ sudo ../bin/wifi-mon -i mon0

The open a browser to the URL: `http://localhost:1234`.
