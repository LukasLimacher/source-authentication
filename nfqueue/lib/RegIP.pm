###############################################################################
#
# Regexp::Common::RegIP
#
# Written by Fabian Hugelshofer, <fh@open.ch>, 19.04.2012
# Adapted by Lukas Limacher, <lul@open.ch>, <limlukas@ethz.ch>, 02.07.2015
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# Regular expression for IPv4 for Regexp::Common
#
###############################################################################

package Regexp::Common::RegIP;

use strict;
use warnings;

use Regexp::Common qw /no_defaults/;

### general regexps

Regexp::Common::pattern
    name    => [ qw(RegIP byte) ],
    create  => qr/(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])/;
;


### network regexps

# IPv4 addresses
Regexp::Common::pattern
    name    => [ qw(RegIP net IP4) ],
    create  => qr/(?:$RE{RegIP}{byte}\.$RE{RegIP}{byte}\.$RE{RegIP}{byte}\.$RE{RegIP}{byte})/,
;

1;
