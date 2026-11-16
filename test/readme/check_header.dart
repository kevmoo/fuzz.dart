void checkHeader(int magic, String tag) {
  if (magic == 0xCAFEBABE) {
    if (tag == 'FUZZ') {
      throw StateError('Reached deep state!');
    }
  }
}
