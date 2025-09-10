import sys

sys.setrecursionlimit(324523409)


class FuckUp(Exception):
    def __init__(self):
        print("This is a way to define functions using Exceptions")
        self.definefunction()

    def definefunction(self):
            def test(input):
                print(input)
            self.test = test





if __name__ == '__main__':
    try:
        raise FuckUp

    except FuckUp as e:
        e.test(33)
        print("Caught the FuckUp exception")
        print(e)