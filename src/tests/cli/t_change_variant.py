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

# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.

import testutils
if __name__ == "__main__":
        testutils.setup_environment("../../../proto")
import pkg5unittest

import errno
import os
import re
import unittest

# needed to get variant settings
import pkg.client.imageconfig as imageconfig

class TestPkgChangeVariant(pkg5unittest.SingleDepotTestCase):
        # Only start/stop the depot once (instead of for every test)
        persistent_setup = True

        pkg_i386 = """
        open pkg_i386@1.0,5.11-0
        add set name=variant.arch value=i386
        add dir mode=0755 owner=root group=bin path=/shared
        add dir mode=0755 owner=root group=bin path=/unique
        add file tmp/pkg_i386/shared/pkg_i386_shared mode=0555 owner=root group=bin path=shared/pkg_arch_shared variant.arch=i386
        add file tmp/pkg_i386/unique/pkg_i386 mode=0555 owner=root group=bin path=unique/pkg_i386 variant.arch=i386
        close"""

        pkg_sparc = """
        open pkg_sparc@1.0,5.11-0
        add set name=variant.arch value=sparc
        add dir mode=0755 owner=root group=bin path=/shared
        add dir mode=0755 owner=root group=bin path=/unique
        add file tmp/pkg_sparc/shared/pkg_sparc_shared mode=0555 owner=root group=bin path=shared/pkg_arch_shared variant.arch=sparc
        add file tmp/pkg_sparc/unique/pkg_sparc mode=0555 owner=root group=bin path=unique/pkg_sparc variant.arch=sparc
        close"""

        pkg_shared = """
        open pkg_shared@1.0,5.11-0
        add set name=variant.arch value=sparc value=i386 value=zos
        add dir mode=0755 owner=root group=bin path=/shared
        add dir mode=0755 owner=root group=bin path=/unique
        add file tmp/pkg_shared/shared/common mode=0555 owner=root group=bin path=shared/common
        add file tmp/pkg_shared/shared/pkg_shared_i386 mode=0555 owner=root group=bin path=shared/pkg_shared variant.arch=i386
        add file tmp/pkg_shared/shared/pkg_shared_sparc mode=0555 owner=root group=bin path=shared/pkg_shared variant.arch=sparc
        add file tmp/pkg_shared/shared/global_motd mode=0555 owner=root group=bin path=shared/zone_motd variant.opensolaris.zone=global
        add file tmp/pkg_shared/shared/nonglobal_motd mode=0555 owner=root group=bin path=shared/zone_motd variant.opensolaris.zone=nonglobal
        add file tmp/pkg_shared/unique/global mode=0555 owner=root group=bin path=unique/global variant.opensolaris.zone=global
        add file tmp/pkg_shared/unique/nonglobal mode=0555 owner=root group=bin path=unique/nonglobal variant.opensolaris.zone=nonglobal

        close"""

        # this package intentionally has no variant.arch specification.
        pkg_inc = """
        open pkg_inc@1.0,5.11-0
        add depend fmri=pkg_i386@1.0,5.11-0 type=incorporate
        add depend fmri=pkg_sparc@1.0,5.11-0 type=incorporate
        add depend fmri=pkg_shared@1.0,5.11-0 type=incorporate
        close"""

        pkg_cluster = """
        open pkg_cluster@1.0,5.11-0
        add set name=variant.arch value=sparc value=i386 value=zos
        add depend fmri=pkg_i386@1.0,5.11-0 type=require variant.arch=i386
        add depend fmri=pkg_sparc@1.0,5.11-0 type=require variant.arch=sparc
        add depend fmri=pkg_shared@1.0,5.11-0 type=require
        close"""

        pkg_list_all = set([
            "pkg_i386",
            "pkg_sparc",
            "pkg_shared",
            "pkg_inc",
            "pkg_cluster"
        ])

        misc_files = [
            "tmp/pkg_i386/shared/pkg_i386_shared",
            "tmp/pkg_i386/unique/pkg_i386",

            "tmp/pkg_sparc/shared/pkg_sparc_shared",
            "tmp/pkg_sparc/unique/pkg_sparc",

            "tmp/pkg_shared/shared/common",
            "tmp/pkg_shared/shared/pkg_shared_i386",
            "tmp/pkg_shared/shared/pkg_shared_sparc",
            "tmp/pkg_shared/shared/global_motd",
            "tmp/pkg_shared/shared/nonglobal_motd",
            "tmp/pkg_shared/unique/global",
            "tmp/pkg_shared/unique/nonglobal"
        ]

        def setUp(self):
                pkg5unittest.SingleDepotTestCase.setUp(self)

                self.make_misc_files(self.misc_files)
                self.pkgsend_bulk(self.rurl, (self.pkg_i386, self.pkg_sparc,
                    self.pkg_shared, self.pkg_inc, self.pkg_cluster))

                # verify pkg search indexes
                self.verify_search = True

                # verify installed images before changing variants
                self.verify_install = False

        def f_verify(self, path, token=None, negate=False):
                """Verify that the specified path exists and contains
                the specified token.  If negate is true, then make sure
                the path doesn't either doesn't exist, or if it does that
                it doesn't contain the specified token."""

                file_path = os.path.join(self.get_img_path(), path)

                try:
                        f = file(file_path)
                except IOError, e:
                        if e.errno == errno.ENOENT and negate:
                                return
                        raise

                if negate and not token:
                        self.assert_(False,
                            "File exists when it shouldn't: %s" % path)

                token_re = re.compile(
                    "^"     + token  + "$"   \
                    "|^"    + token + "[/_]" \
                    "|[/_]" + token + "$"    \
                    "|[/_]" + token + "[/_]")

                found = False
                for line in f:
                        if token_re.search(line):
                                found=True
                                break
                f.close()

                if not negate and not found:
                        self.assert_(False, "File %s (%s) does not contain %s" %
                            (path, file_path, token))
                if negate and found:
                        self.assert_(False, "File %s (%s) contains %s" %
                            (path, file_path, token))

        def p_verify(self, p=None, v_arch=None, v_zone=None, negate=False):
                """Given a specific architecture and zone variant, verify
                the contents of the specified within an image.  If
                negate is true then verify that the package isn't
                installed, and that actions delivered by the package
                don't exist in the target image.

                This routine has hard coded knowledge of the test package
                names, variants, and dependancies.  So any updates made
                to the test package will also likely required updates to
                this function."""

                assert p != None
                assert v_arch == 'i386' or v_arch == 'sparc' or v_arch == 'zos'
                assert v_zone == 'global' or v_zone == 'nonglobal'

                # make sure the package is installed
                if negate:
                        self.pkg("list %s" % p, exit=1)
                else:
                        self.pkg("list %s" % p)
                        self.pkg("verify %s" % p)

                # nothing to verify for packages with no content
                if p == 'pkg_inc':
                        return
                if p == 'pkg_cluster':
                        return

                # verify package contents
                if p == 'pkg_i386':
                        assert negate or v_arch == 'i386'
                        self.f_verify("shared/pkg_arch_shared", "i386", negate)
                        self.f_verify("unique/pkg_i386", "i386", negate)
                        return
                elif p == 'pkg_sparc':
                        assert negate or v_arch == 'sparc'
                        self.f_verify("shared/pkg_arch_shared", "sparc", negate)
                        self.f_verify("unique/pkg_sparc", "sparc", negate)
                        return
                elif p == 'pkg_shared':
                        self.f_verify("shared/common", "common", negate)
                        self.f_verify("shared/pkg_shared", v_arch, negate)
                        self.f_verify("shared/zone_motd", v_zone, negate)
                        if negate:
                                self.f_verify("unique/global", v_zone, True)
                                self.f_verify("unique/nonglobal", v_zone, True)
                        elif v_zone == 'global':
                                self.f_verify("unique/global", v_zone, False)
                                self.f_verify("unique/nonglobal", v_zone, True)
                        elif v_zone == 'nonglobal':
                                self.f_verify("unique/global", v_zone, True)
                                self.f_verify("unique/nonglobal", v_zone, False)
                        return

                # NOTREACHED
                assert False

        def i_verify(self, v_arch=None, v_zone=None, pl=None):
                """Given a specific architecture variant, zone variant,
                and package list, verify that the variant settings are
                correct for the current image, and that the image
                contains the specified packages.  Also verify that the
                image doesn't contain any other unexpected packages.

                This routine has hard coded knowledge of the test package
                names, variants, and dependancies.  So any updates made
                to the test package will also likely required updates to
                this function."""

                assert v_arch == 'i386' or v_arch == 'sparc' or v_arch == 'zos'
                assert v_zone == 'global' or v_zone == 'nonglobal'

                if pl == None:
                        pl = []

                # verify the variant settings
                ic = imageconfig.ImageConfig(self.get_img_path(), "publisher")
                ic.read(os.path.join(self.get_img_path(), "var/pkg"))

                if "variant.arch" not in ic.variants:
                        self.assert_(False,
                            "unable to determine image arch variant")
                if ic.variants["variant.arch"] != v_arch:
                        self.assert_(False, "unexpected arch variant")

                if "variant.opensolaris.zone" not in ic.variants:
                        self.assert_(False,
                            "unable to determine image zone variant")
                if ic.variants["variant.opensolaris.zone"] != v_zone:
                        self.assert_(False, "unexpected zone variant")


                # adjust the package list based on known dependancies.
                if 'pkg_cluster' in pl and 'pkg_shared' not in pl:
                        pl.append('pkg_shared')
                if v_arch == 'i386':
                        if 'pkg_cluster' in pl and 'pkg_i386' not in pl:
                                pl.append('pkg_i386')
                elif v_arch == 'sparc':
                        if 'pkg_cluster' in pl and 'pkg_sparc' not in pl:
                                pl.append('pkg_sparc')

                #
                # Make sure the number of packages installed matches the
                # number of packages in pl.
                #
                self.pkg(
                    "list -H | wc -l | nawk '{print $1'} | grep '^%d$'" %
                    len(pl))

                # make sure each specified package is installed
                for p in pl:
                        self.p_verify(p, v_arch, v_zone)

                for p in (self.pkg_list_all - set(pl)):
                        self.p_verify(p, v_arch, v_zone, negate=True)

                # make sure that pkg search doesn't report corrupted indexes
                if self.verify_search:
                        for p in pl:
                                self.pkg("search -l %s" % p )

        def cv_test(self, v_arch, v_zone, pl, v_arch2, v_zone2, pl2):
                """ test if change-variant works """

                assert v_arch == 'i386' or v_arch == 'sparc' or v_arch == 'zos'
                assert v_arch2 == 'i386' or v_arch2 == 'sparc' or \
                    v_arch2 == 'zos'
                assert v_zone == 'global' or v_zone == 'nonglobal'
                assert v_zone2 == 'global' or v_zone2 == 'nonglobal'

                # create an image
                variants = {
                    "variant.arch": v_arch,
                    "variant.opensolaris.zone": v_zone
                }
                self.image_create(self.rurl, variants=variants)
                self.pkg("variant -H| egrep %s" % ("'variant.arch[ ]*%s'" % v_arch))
                self.pkg("variant -H| egrep %s" % ("'variant.opensolaris.zone[ ]*%s'" % v_zone))

                # install the specified packages into the image
                ii_args = "";
                for p in pl:
                        ii_args += " %s " % p
                self.pkg("install %s" % ii_args)

                # if we're paranoid, then verify the image we just installed
                if self.verify_install:
                        self.i_verify(v_arch, v_zone, pl)
                # change the specified variant
                cv_args = "";
                cv_args += " -v";
                cv_args += " variant.arch=%s" % v_arch2
                cv_args += " variant.opensolaris.zone=%s" % v_zone2
                self.pkg("change-variant -v" + cv_args)
                # verify the updated image
                self.i_verify(v_arch2, v_zone2, pl2)

                self.pkg("variant -H| egrep %s" % ("'variant.arch[ ]*%s'" % v_arch2))
                self.pkg("variant -H| egrep %s" % ("'variant.opensolaris.zone[ ]*%s'" % v_zone2))

                self.image_destroy()

        def test_cv_01_none_1(self):
                self.cv_test("i386", "global", ["pkg_cluster",],
                    "i386", "global", ["pkg_cluster"])

        def test_cv_01_none_2(self):
                self.cv_test("i386", "nonglobal", ["pkg_cluster",],
                    "i386", "nonglobal", ["pkg_cluster"])

        def test_cv_01_none_3(self):
                self.cv_test("sparc", "global", ["pkg_cluster",],
                    "sparc", "global", ["pkg_cluster"])

        def test_cv_01_none_4(self):
                self.cv_test("sparc", "nonglobal", ["pkg_cluster",],
                    "sparc", "nonglobal", ["pkg_cluster"])

        def test_cv_02_arch_1(self):
                self.cv_test("i386", "global", ["pkg_shared"],
                    "sparc", "global", ["pkg_shared"])

        def test_cv_02_arch_2(self):
                self.cv_test("sparc", "global", ["pkg_shared"],
                    "i386", "global", ["pkg_shared"])

        def test_cv_03_arch_1(self):
                self.cv_test("i386", "global", ["pkg_inc",],
                    "sparc", "global", ["pkg_inc"])

        def test_cv_03_arch_2(self):
                self.cv_test("sparc", "global", ["pkg_inc"],
                    "i386", "global", ["pkg_inc"])

        def test_cv_04_arch_1(self):
                self.cv_test("i386", "global", ["pkg_i386"],
                    "sparc", "global", [])

        def test_cv_04_arch_2(self):
                self.cv_test("sparc", "global", ["pkg_sparc"],
                    "i386", "global", [])

        def test_cv_05_arch_1(self):
                self.cv_test("i386", "global",
                    ["pkg_i386", "pkg_shared", "pkg_inc"],
                    "sparc", "global", ["pkg_shared", "pkg_inc"])

        def test_cv_05_arch_2(self):
                self.cv_test("sparc", "global",
                    ["pkg_sparc", "pkg_shared", "pkg_inc"],
                    "i386", "global", ["pkg_shared", "pkg_inc"])

        def test_cv_06_arch_1(self):
                self.cv_test("i386", "global", ["pkg_cluster",],
                    "sparc", "global", ["pkg_cluster"])

        def test_cv_06_arch_2(self):
                self.cv_test("sparc", "global", ["pkg_cluster"],
                    "i386", "global", ["pkg_cluster"])

        def test_cv_07_arch_1(self):
                self.cv_test("i386", "global", ["pkg_cluster", "pkg_inc"],
                    "sparc", "global", ["pkg_cluster", "pkg_inc"])

        def test_cv_07_arch_2(self):
                self.cv_test("sparc", "global", ["pkg_cluster", "pkg_inc"],
                    "i386", "global", ["pkg_cluster", "pkg_inc"])

        def test_cv_08_zone_1(self):
                self.cv_test("i386", "global", ["pkg_cluster",],
                    "i386", "nonglobal", ["pkg_cluster"])

        def test_cv_08_zone_2(self):
                self.cv_test("i386", "nonglobal", ["pkg_cluster"],
                    "i386", "global", ["pkg_cluster"])

        def test_cv_09_zone_1(self):
                self.cv_test("sparc", "global", ["pkg_cluster",],
                    "sparc", "nonglobal", ["pkg_cluster"])

        def test_cv_09_zone_2(self):
                self.cv_test("sparc", "nonglobal", ["pkg_cluster"],
                    "sparc", "global", ["pkg_cluster"])

        def test_cv_10_arch_and_zone_1(self):
                self.cv_test("i386", "global", ["pkg_cluster",],
                    "sparc", "nonglobal", ["pkg_cluster"])

        def test_cv_10_arch_and_zone_2(self):
                self.cv_test("sparc", "nonglobal", ["pkg_cluster"],
                    "i386", "global", ["pkg_cluster"])

        def test_cv_11_arch_and_zone_1(self):
                self.cv_test("i386", "nonglobal", ["pkg_cluster",],
                    "sparc", "global", ["pkg_cluster"])

        def test_cv_11_arch_and_zone_2(self):
                self.cv_test("sparc", "global", ["pkg_cluster"],
                    "i386", "nonglobal", ["pkg_cluster"])


if __name__ == "__main__":
        unittest.main()
