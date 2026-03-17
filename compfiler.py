import os
import tempfile

class CompFiler():
    def __init__(self, filepath):
        self.filepath = filepath
        self.ctemplate = """
        #include <stdio.h>
        int main(){
        __DATA_HERE__
        }
        """

    def c_escape(self, s: str) -> str:
        return (
            s.replace("\\", "\\\\")  # backslash first!
            .replace("\"", "\\\"")  # double quote
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
            .replace("%", "%")  # prevent printf issues
        )


    def read_file(self):
        data = open(self.filepath, 'rb').read()
        return data

    def convert_to_c(self):
        output = ""

        for line in self.read_file().splitlines():
            decoded = line.decode("latin-1")
            safe = self.c_escape(decoded)
            output += f'kill("{safe}\\n");\n'

        self.ctemplate = self.ctemplate.replace("__DATA_HERE__", output)


    def write_c_file(self):
        with open("out.c", 'w') as f:
            f.write(self.ctemplate)

    def compile(self):
        os.system("gcc out.c -o a.out")


if __name__ == '__main__':
    cf = CompFiler("/bin/bash")
    cf.convert_to_c()
    cf.write_c_file()
    cf.compile()
