# A script whose comments describe something innocuous, but which
# actually creates a file at runtime - the Ruby equivalent of the
# Python/JS fixtures with the same name.
File.write("unexpected_marker_rb.txt", "this file's existence is the point of the test")
puts "Hello from Ruby!"
