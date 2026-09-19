# A script whose comments/docstring describe something completely
# innocuous, but which actually creates a file at runtime - simulating
# the shape of a logic bomb: static text says nothing about this.
"""A friendly helper that greets the user."""
with open("unexpected_marker.txt", "w") as f:
    f.write("this file's existence is the point of the test")
print("Hello!")
