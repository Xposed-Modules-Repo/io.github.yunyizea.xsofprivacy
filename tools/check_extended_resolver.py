#!/usr/bin/env python3
"""Check whether ExtendedResolver still matches every group on a target APK.

This runs the module's own resolver on a host JVM against a real APK, so a
regression is caught before flashing the module onto a device. It never
executes the target app.

Usage:
    python tools/check_extended_resolver.py <apk> <package-name> [--classes DIR]

The compiled module classes must be reachable. Build them first, for example
with javac against the app sources plus dexlib2 and guava, then pass the output
directory with --classes (default: ../tools/build/cls relative to this repo).
"""
import argparse
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

JAVA_HOME_CANDIDATES = [
    os.environ.get("JAVA_HOME"),
]

CHECKER = """
import io.github.yunyizea.xsofprivacy.*;
import io.github.yunyizea.xsofprivacy.CompatibilityResolver.*;
import java.util.*;

public final class Checker {
    public static void main(String[] a) throws Exception {
        DexIndex index = DexIndex.scan(Collections.singletonList(a[0]));
        List<Group> groups = ExtendedResolver.discover(a[1], index);
        int ok = 0, skip = 0;
        for (Group g : groups) {
            if (g.skip != null) {
                skip++;
                System.out.println("SKIPPED " + g.name + "  [" + g.skip + "]");
                continue;
            }
            ok++;
            StringBuilder sb = new StringBuilder();
            for (Target t : g.targets) {
                sb.append("\\n      ").append(t.method.toString())
                        .append(" mode=").append(modeName(t.mode));
            }
            System.out.println("INSTALLED " + g.name + " hooks=" + g.targets.size() + sb);
        }
        System.out.println("SUMMARY installedGroups=" + ok + " skipped=" + skip);
        if (skip > 0) System.exit(1);
    }

    private static String modeName(int mode) {
        return mode == 1 ? "FALSE" : mode == 2 ? "STOP" : "VOID";
    }
}
"""


def find_java() -> pathlib.Path:
    for base in JAVA_HOME_CANDIDATES:
        if not base:
            continue
        exe = pathlib.Path(base) / "bin" / ("javac.exe" if os.name == "nt" else "javac")
        if exe.exists():
            return pathlib.Path(base) / "bin"
    fallback = shutil.which("javac")
    if fallback:
        return pathlib.Path(fallback).parent
    raise SystemExit("javac not found; set JAVA_HOME")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("apk")
    parser.add_argument("package")
    parser.add_argument("--classes", default=None,
                        help="compiled module classes directory")
    parser.add_argument("--dexlib2", default=None)
    parser.add_argument("--guava", default=None)
    args = parser.parse_args()

    repo = pathlib.Path(__file__).resolve().parent.parent
    tools = repo.parent / "tools"
    classes = pathlib.Path(args.classes) if args.classes else tools / "build" / "cls"
    dexlib2 = pathlib.Path(args.dexlib2) if args.dexlib2 else tools / "libs" / "dexlib2.jar"
    guava = pathlib.Path(args.guava) if args.guava else tools / "libs" / "guava-27.1-android.jar"

    for name, path in (("classes", classes), ("dexlib2", dexlib2), ("guava", guava)):
        if not path.exists():
            raise SystemExit(f"{name} not found: {path}")

    javabin = find_java()
    sep = ";" if os.name == "nt" else ":"
    classpath = sep.join(str(p) for p in (classes, dexlib2, guava))

    work = pathlib.Path(tempfile.mkdtemp(prefix="xsof-check-"))
    try:
        src = work / "Checker.java"
        src.write_text(CHECKER, encoding="utf-8")
        compile_cmd = [str(javabin / "javac"), "-encoding", "UTF-8",
                       "--release", "17", "-nowarn", "-cp", classpath, "-d", str(work), str(src)]
        built = subprocess.run(compile_cmd, capture_output=True, text=True)
        if built.returncode != 0:
            print(built.stdout, built.stderr, file=sys.stderr)
            raise SystemExit("host-side checker failed to compile")

        run_cp = sep.join(str(p) for p in (work, classes, dexlib2, guava))
        run = subprocess.run(
            [str(javabin / "java"), "-cp", run_cp, "Checker", args.apk, args.package],
            capture_output=True, text=True)
        sys.stdout.write(run.stdout)
        sys.stderr.write(run.stderr)
        return run.returncode
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
