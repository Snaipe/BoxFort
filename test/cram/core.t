Testing basic samples

  $ nested.c.bin
  I am a worker!
  I am a nested worker!

Testing whether the callbacks are working

  $ callback.c.bin
  Child exited with code 5

Testing if the context sample behave as expected

  $ context.c.bin
  my_int = 42
  my_long = 24
