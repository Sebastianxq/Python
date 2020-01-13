As it currently stands, the file input is guided, meaning
that you must first start the program and then specify the file you will be
sending over to the server. The only requirement in terms of file inputs is
that the file MUST exists within this directory, otherwise the program will
fail and disconnect before sending anything to the server.

TODO:
1.)Incorperate a timeout feature on the client
2.)Send in a total packet count with the title (used for acks)
3.)Maybe cut out the input line and just have it specified through sys.args[]
4.)How to cutoff at the end when the entire file is recv'd
