## TUMCTF: httpd

---------------
## Write-up

So the challenge has an http server, and we were given its binary.
First thing we did was to go in to that server, and there was a link to the flag. Ofcourse, it wasn't really the flag.
Something redirected, or blocked us. We started looking into the binary. It looks like the http server is started with
a whitelist of files, and can only display these files. We guess that the following commandline started the server:
`./httpd index.html no.html`
The first argument is the default file - the file to open if a get request to an unknown page (a page not within the commandline
arguments) is recieved. So any request not to `index.html` or `no.html` will cause the server to serve `index.html`.
Also, an unknown filename will cause a printf to stderr, printing the filename that wasn't found.
The filename is given to printf as the format string.

So we have a format string to our choice. But what can we do?
Well, it seems like a pointer to the first argument (`index.html`) is stored on the stack.
If we can write to it, we can change it to `flag`, and any not found page will cause `flag` to be read :)

But how can we write to it the value flag?
printf's `%n` lets you write the number of characters outputed by printf so far to an argument of type `int*`.
It means, we can write `flag` bytes, and use %n to write to a printf parameter (some argument on the stack. in
our case, the pointer to the first argument).
Well, this still isn't good enough, because we need to null-terminate the string.
Apparently we can use `%lln` to write the number of characters outputed to an argument of type `long long*` - write
8 bytes :)

So all we need to do is output `flag` bytes, and place %lln afterwards.
Sadly, the size of the buffer that is used to store our url is only about `2**15` bytes.
By using `%1734437990X%`, we printed a single value, padded to `1734437990` chars.
Another cool thing is that we can print to a specific parameter - `%5$lln` is like `%lln`, only that it
is for the fifth parameter of printf, and not for the next parameter.

So the requests that we need to send to the server are:

```
GET %1734437990X%5$llnn
GET /anything
```

And the content of `flag` will be printed :)

if you run `httpd` locally, you should pipe stderr to `/dev/null`, because there is a lot of output
in stderr that you probably don't want to see.