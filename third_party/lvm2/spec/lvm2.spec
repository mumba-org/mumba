# Copyright (C) 2013-2014 Red Hat, Inc. All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# NB. This specfile is a work in progress. It is currently used by the
# continuous integration system driven by nix and hydra to create and test RPMs
# on Fedora, CentOS and RHEL systems. It is not yet ready for deployment of LVM
# on those systems.

# A macro to pull in an include file from an appropriate location.
%define import() %include %(test -e %{S:%1} && echo %{S:%1} || echo %{_sourcedir}/%1)

%import source.inc

# PatchN: nnn.patch goes here

%prep
%setup -q -n LVM2.%{version}

%import build.inc
%import packages.inc

%changelog
