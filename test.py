class l:
    def __init__(self, name):
        self.name = name
        print(self == None)

    def __eq__(self, other):
        return self == self

    def __ne__(self, other):
        return True




a = l(4)
b = l(5)


print(a == b)
print(a != b)

