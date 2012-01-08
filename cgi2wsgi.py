# COPYRIGHT 2010-2011 GRAHAM DUMPLETON

# Robust CGI/WSGI adapter which protects stdin/stdout and
# performs other validity checks on type of status line, headers
# and response data as well as amount of response data produced
# by the WSGI application.

import os
import sys
import cStringIO
import types
import imp
import string


class FileWrapper(object):

    def __init__(self, filelike, blksize=8192):
        self.filelike = filelike
        self.blksize = blksize
        if hasattr(filelike, 'close'):
              self.close = filelike.close

    def __getitem__(self, key):
        data = self.filelike.read(self.blksize)
        if data:
            return data
        raise IndexError

class Adapter(object):

    def __init__(self, application, environ, stdin, stdout, stderr):
        self._application = application

        self._environ = environ

        self._stdin = stdin
        self._stdout = stdout
        self._stderr = stderr

        self._status_line = None
        self._headers = None

        self._content_length = None
        self._output_length = 0

    def validate_headers(self, headers):
        if type(headers) != types.ListType:
            raise TypeError("response headers must be a list")

        for header in headers:
            if type(header) != types.TupleType:
                raise TypeError("list of tuple values expected, "
                                "value of type %s found", type(header))
            elif len(header) != 2:
                raise TypeError("tuple of length 2 expected, length "
                                "is %d", len(header))

            name, value = header
            if type(name) != types.StringType:
                raise TypeError("expected byte string object for header "
                                "name, value of type %s found", type(name))
            if type(name) != types.StringType:
                raise TypeError("expected byte string object for header "
                                "value, value of type %s found", type(value))
            if name.find('\n') != -1 or value.find('\n') != -1:
                raise TypeError("embedded newline in response header "
                                "with name '%s' and value '%s'", name, value)

            if name.lower() == 'content-length':
                try:
                    length = string.atoi(value)
                except:
                    raise ValueError("invalid content length")
                if length < 0:
                    raise ValueError("invalid content length")

    def validate_output(self, data):

        # Data being written should be a byte string only.

        if type(data) != types.StringType:
            raise TypeError("byte string value expected, value "
                            "of type %s found", type(data))

    def write_output(self, data):

        # Validate type of data being output.

        self.validate_output(data)

        # Before we can write any data, then start_response()
        # must have been called. Note that yielding of empty
        # values prior to start_response() being called is
        # picked up as special case in processing of the
        # iterable returned from the application, with such
        # empty values being ignored.

        if not self._status_line:
            raise RuntimeError("response has not been started")

        # If haven't sent the headers as yet, then do so. We
        # cache the content length so know how much data the
        # application is expected to generate.

        if self._headers is not None:
            self._stdout.write('Status: %s\r\n' % self._status_line)
            for header in self._headers:
                if header[0].lower() == 'content-length':
                    self._content_length = int(header[1])
                self._stdout.write('%s: %s\r\n' % header)

            # Terminate list of headers written out.

            self._stdout.write('\r\n')
  
            # Record that we have now sent the headers.

            self._headers = None

            # If no actual data, explicitly flush output stream
            # to ensure that headers are sent as we would
            # otherwise skip flushing output stream if no data.

            if not data or self._content_length == 0:
                self._stdout.flush()

        # If there is output data and content length was
        # specified, ensure that we don't actually output more
        # data than was specified as being sent as otherwise
        # technically in violation HTTP specifications.

        if data:
            length = len(data)
            if self._content_length is not None:
                if self._output_length < self._content_length:
                    if self._output_length + length > self._content_length:
                        data = data[:self._content_length-self._output_length]
                else:
                    data = ''

            self._output_length += length

        # Write out any actual data and flush output stream to
        # ensure that it is sent.

        if data:
            self._stdout.write(data)
            self._stdout.flush()

    def start_response(self, status_line, headers, exc_info=None):

        # Validate headers supplied.

        self.validate_headers(headers)

        # Handle start_response() being called a second time to
        # change status line and headers when an exception has
        # occurred during generation of body content. If called
        # a second time with no exception then it is an error.

        if exc_info:
            try:
                if self._status_line and self._headers is None:

                    # If the headers have already been sent, we
                    # need to raise again the supplied exception
                    # with expectation that the request will be
                    # totally aborted. If headers haven't been
                    # sent, then replace the existing status
                    # line and headers with subsequent values
                    # supplied.

                    raise exc_info[0], exc_info[1], exc_info[2]
            finally:
                    
                # Make sure that any circular reference for
                # the exception details is broken to avoid a
                # resource leakage.

                exc_info = None

        elif self._status_line and self._headers is None:
            raise RuntimeError("headers have already been sent")

        # Cache status line and headers. Make sure we make a
        # copy of the list containing the headers so that the
        # application cant modify the set of headers after
        # making this call.

        self._status_line = status_line
        self._headers = list(headers)

        # Return the callable for explicitly writing output.
        # This is to support old style web applications that
        # cant yield response as iterable of some form.

        return self.write_output

    def handle_request(self):

        # We shouldn't need to wrap sys.stdin so as to limit
        # data able to be read as the web server invoking the
        # CGI script should already ensure that an empty string
        # is returned as end sentinel when all request content
        # is exhausted. Note that there still might actually be
        # more content than as specified by the content length
        # request header. This is because input filters in
        # Apache or other web servers may mutate the input data
        # stream and change its length without updating the
        # request content length. Technically speaking WSGI
        # applications aren't able to support such input filters
        # as not meant to read more input data than specified by
        # the content length. That is arguable a flaw in the WSGI
        # specification though. So as to allow applications that
        # still want to access all such data, don't chop off
        # input data at content length and provide access to all
        # of it. This shouldn't be an issue for a so called
        # conforming WSGI applications as they aren't meant to
        # read more than what is defined by the request content
        # length.

        self._environ['wsgi.input'] = self._stdin

        # Assume that stderr automatically flushes any output
        # immediately.

        self._environ['wsgi.errors'] = self._stderr

        # Identify ourselves as WGSI 1.0 even though we support
        # size hint for readline().

        self._environ['wsgi.version'] = (1, 0)

        # Define process/threading model. Processes aren't
        # persistent, so no browser based debuggers that are
        # dependent on state being retained between requests
        # will work.

        self._environ['wsgi.multithread'] = False
        self._environ['wsgi.multiprocess'] = True
        self._environ['wsgi.run_once'] = True

        # For CGI, the customary method used by web servers to
        # indicate that 'https' is being used, is to set 'HTTPS'
        # variable in process environment variables. We need to
        # set 'wsgi.url_scheme' instead. In doing this, we
        # delete the 'HTTPS' variable from the WSGI environment
        # as WSGI applications are meant to use the variable
        # 'wsgi.url_scheme' instead and thus want to discourage
        # checking for 'HTTPS'.

        if self._environ.pop('HTTPS','off').lower() in ('on','1'):
            self._environ['wsgi.url_scheme'] = 'https'
        else:
            self._environ['wsgi.url_scheme'] = 'http'

        # Add in FileWrapper class object for 'wsgi.file_wrapper'.
        # We don't actually provide an platform specific optimised
        # version of this, but this should really be mandatory to
        # be supplied even if not optimised so that users don't
        # need to provide their own implementation.

        self._environ['wsgi.file_wrapper'] = FileWrapper

        # Result from WSGI application should be an iterable. We
        # loop over that and write out data until reach amount as
        # specified by a response 'Content-Length' header or until
        # all consumed if no content length specified for response.

        result = self._application(self._environ, self.start_response)

        try:
            for data in result:

                # Ignore any empty values yielded. This is
                # especially important as any initial empty values
                # shouldn't cause response headers to be flushed.
                # Any encountered after first non empty value can
                # also be ignored as nothing to do anyway.

                if data:
                    self.write_output(data)

                # Break out of loop if more data has been sent
                # than specified by response content length.

                if self._content_length is not None:
                    if self._output_length >= self._content_length:
                        break

            # If we have reached the end of input and there were no
            # non empty values yielded, must still write an empty
            # string to cause the response headers themselves to be
            # written.

            if self._headers is not None:
                self.write_output('')

        finally:

            # Must always call close() on the iterable returned by
            # the application to give it the chance to cleanup any
            # resources which it had made use of.

            if hasattr(result, 'close'):
                result.close()

class Script(object):

    def __init__(self, filename):
        self._filename = filename

    def __call__(self, environ, start_response):

        # Load the target WSGI script file into a dummy module.

        module = imp.new_module('__wsgi__')
        module.__file__ = self._filename
        execfile(self._filename, module.__dict__)
        sys.modules['__wsgi__'] = module

        # Lookup and execute the WSGI application.

        application = getattr(module, 'application')

        return application(environ, start_response)

def redirect_handler(environ, start_response):

    redirect_handler = environ.get('REDIRECT_HANDLER')

    assert redirect_handler == 'cgi2wsgi'

    path_translated = environ.get('PATH_TRANSLATED')
    script_name = environ.get('PATH_INFO')
    path_info = []

    while not os.path.exists(path_translated):
        path_translated = os.path.split(path_translated)[0]
        script_name, path = os.path.split(script_name)
        path_info.insert(0, path)

    if path_info:
        path_info.insert(0, '')

    path_info = '/'.join(path_info)

    script = Script(path_translated)

    environ['SCRIPT_NAME'] = script_name
    environ['PATH_INFO'] = path_info

    return script(environ, start_response)

def cgi_script_handler():

    # Keep a reference to the original stdin. We then replace
    # stdin with an empty stream. This is to protect against
    # code from accessing sys.stdin directly and consuming the
    # request content.

    stdin = sys.stdin

    sys.stdin = cStringIO.StringIO('')

    # Keep a reference to the original stdout. We then replace
    # stdout with stderr. This is to protect against code that
    # wants to use 'print' to output debugging. If stdout wasn't
    # protected, then anything output using 'print' would end up
    # being sent as part of the response itself and interfere
    # with the operation of the CGI protocol.

    stdout = sys.stdout

    sys.stdout = sys.stderr

    # Use the original stderr as is for errors.

    stderr = sys.stderr

    # Use a copy of the process environment as we want to
    # populate it with additional WSGI specific variables and
    # don't want to be polluting the process environment
    # variables with those as they would then be inherited by
    # sub processes.

    environ = dict(os.environ.items())

    # Target WSGI script file is dictated by value of the
    # variable SCRIPT_FILENAME in CGI environment.

    filename = environ['SCRIPT_FILENAME']

    # Create adapter for the WSGI application contained in
    # the WSGI script file.

    script = Script(filename)

    # Create CGI/WSGI bridge wrapping the 'application' entry
    # point in the target WSGI script file along with the
    # current request context. We only use the object once and
    # then the process exits, so doesn't matter it isn't
    # reusable or thread safe.

    adapter = Adapter(script, environ, stdin, stdout, stderr)

    # Execute the application.

    adapter.handle_request()

if __name__ == '__main__':
    cgi_script_handler()
