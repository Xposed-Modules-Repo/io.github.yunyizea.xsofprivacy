"""Host-only matcher tests: python tools/run_resolver_tests.py /path/to/phone-manager.apk.
Downloads pinned Maven dependencies into a temporary directory. Needs Java 17 with
jdk.compiler. Does not execute or modify the supplied APK.
"""
from pathlib import Path
import hashlib
import os
import subprocess
import sys
import tempfile
import urllib.request

DEPENDENCIES = [
    ("org/smali/dexlib2/2.5.2/dexlib2-2.5.2.jar",
     "5a5c8982d8bd7d6e3bb1a0713049e3c78b719ec32b20f6b619885cec30a0dd61"),
    ("com/google/guava/guava/27.1-android/guava-27.1-android.jar",
     "686404f2d1d4d221911f96bd627ff60dac2226a5dfa6fb8ba517073eb97ec0ef"),
    ("com/google/guava/failureaccess/1.0.1/failureaccess-1.0.1.jar",
     "a171ee4c734dd2da837e4b16be9df4661afab72a41adaf31eb84dfdaf936ca26"),
]


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python tools/run_resolver_tests.py phone-manager.apk")
    apk = Path(sys.argv[1]).resolve(strict=True)
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="xsof-host-tests-") as work:
        work = Path(work)
        jars = []
        for coordinate, checksum in DEPENDENCIES:
            jar = work / coordinate.rsplit("/", 1)[-1]
            with urllib.request.urlopen("https://repo.maven.apache.org/maven2/" + coordinate,
                                        timeout=60) as response:
                data = response.read()
            if hashlib.sha256(data).hexdigest() != checksum:
                raise RuntimeError("Dependency integrity check failed: " + jar.name)
            jar.write_bytes(data)
            jars.append(str(jar))
        classpath = os.pathsep.join(jars)
        classes = work / "classes"
        classes.mkdir()
        source = root / "app/src/main/java/local/xsofprivacy"
        files = [source / "DexIndex.java", source / "CompatibilityResolver.java",
                 root / "tests/ResolverTest.java"]
        subprocess.run(["java", "com.sun.tools.javac.Main", "-source", "17", "-target", "17",
                        "-classpath", classpath, "-d", str(classes), *map(str, files)], check=True)
        subprocess.run(["java", "-Xmx512m", "-cp", str(classes) + os.pathsep + classpath,
                        "local.xsofprivacy.ResolverTest", str(apk)], check=True)


if __name__ == "__main__":
    main()
