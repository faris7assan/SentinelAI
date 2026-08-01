import time
import sys


def main():
    print("Mock service starting")
    sys.stdout.flush()
    try:
        count = 0
        while True:
            count += 1
            print(f"mock: heartbeat {count}")
            sys.stdout.flush()
            time.sleep(1)
    except KeyboardInterrupt:
        print("Mock service stopping")
        sys.stdout.flush()


if __name__ == '__main__':
    main()
