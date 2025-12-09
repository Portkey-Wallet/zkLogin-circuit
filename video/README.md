# Video

This video recording showcases the full process of:

- [Compiling Circuits](https://docs.circom.io/getting-started/compiling-circuits/)
- [Computing the witness](https://docs.circom.io/getting-started/computing-the-witness/)
- [Proving circuit](https://docs.circom.io/getting-started/proving-circuits/)

# Recording the video

The video is recorded using [asciinema](https://asciinema.org/docs/getting-started).

```bash
brew install asciinema     # installation
asciinema rec circom.cast  # start the recording, save to the file circom.cast
exit                       # stop the recording
```

# Viewing in browser

```bash
cd video      # this folder
npx serve .   # start a local web server at this path
```

Now visit the url displayed in the terminal to view the video.
