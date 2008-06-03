#!/usr/bin/python
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

"""face - dynamic index page for image packaging server"""

import httplib
import os

# XXX Use small templating module?

try:
        content_root = os.path.join(os.environ['PKG_HOME'], 'share/lib/pkg')
except KeyError:
        content_root = '/usr/share/lib/pkg'

def head(title = "pkg - image packaging system"):
        return ("""\
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
        "http://www.w3.org/TR/2002/REC-xhtml1-20020801/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
 <link rel="shortcut icon" type="image/png" href="/static/pkg-block-icon.png"/>
 <link rel="stylesheet" type="text/css" href="/static/pkg.css"/>
 <title>%s</title>
</head>
""" % title)

def unknown(img, request, response):

        response.status = httplib.NOT_FOUND
        output = head()
        output += """\
<body>
 <div id="doc4" class="yui-t5">
  <div id="hd">
   <h1><img src="/static/pkg-block-logo.png" alt="logo"/> <code>pkg</code> server unknown page</h1>
  </div>
  <div id="bd">
   <div id="yui-main">
    <div class="yui-b">
     <pre>
"""

        output += ('''%d GET URI %s ; headers:\n%s''' %
            (httplib.NOT_FOUND, request.path_info, request.headers))

        output += ("""\
     </pre>
    </div>
   </div>
  </div>
 </div>
</body>
</html>
""")

        return output

def error(img, request, response):
        response.status = httplib.INTERNAL_SERVER_ERROR

        output = head()
        output += """\
<body>
 <div id="doc4" class="yui-t5">
  <div id="hd">
   <h1><img src="/static/pkg-block-logo.png" alt="logo"/> <code>pkg</code> server internal error</h1>
  </div>
  <div id="bd">
   <div id="yui-main">
    <div class="yui-b">
     <pre>
face.response() for %s
     </pre>
    </div>
   </div>
  </div>
 </div>
</body>
</html>
""" % request.path_info

        return output

def index(img, request, response):
        output = head()
        output += ("""\
<body>
 <div id="doc4" class="yui-t5">
  <div id="hd">
   <h1><img src="/static/pkg-block-logo.png" alt="logo"/> <code>pkg</code> server ok</h1>
  </div>
  <div id="bd">
   <div id="yui-main">
    <div class="yui-b">
     <h2>Statistics</h2>
     <pre>
""")
        output += (img.get_status())
        output += ("""\
     </pre>

     <h2>Catalog</h2>
     <pre>
""")
        for f in img.catalog.fmris():
                output += ("%s\n" % f.get_fmri())

        output += ("""\
     </pre>
    </div>
   </div>
  </div>
 </div>
</body>
</html>""")

        return output

pages = {
        "/" : index,
        "/index.html" :  index
}

def set_content_root(path):
        global content_root
        content_root = path

def match(img, request, response):
        if request.path_info in pages:
                return True
        return False

def respond(img, request, response):
        if request.path_info in pages:
                page = pages[request.path_info]
                return page(img, request, response)
        else:
                return error(img, request, response)

