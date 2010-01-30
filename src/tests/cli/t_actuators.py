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

# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

import testutils
if __name__ == "__main__":
        testutils.setup_environment("../../../proto")
import pkg5unittest

import os
import unittest
import shutil

from pkg import misc

class TestPkgActuators(pkg5unittest.SingleDepotTestCase):
        # Only start/stop the depot once (instead of for every test)
        persistent_setup = True

        misc_files = { \
                "svcprop_enabled" :
"""general/enabled boolean true
general/entity_stability astring Unstable
general/single_instance boolean true
restarter/start_pid count 4172
restarter/start_method_timestamp time 1222382991.639687000
restarter/start_method_waitstatus integer 0
restarter/transient_contract count
restarter/auxiliary_state astring none
restarter/next_state astring none
restarter/state astring online
restarter/state_timestamp time 1222382991.644413000
restarter_actions/refresh integer
restarter_actions/maint_on integer
restarter_actions/maint_off integer
restarter_actions/restart integer
local-filesystems/entities fmri svc:/system/filesystem/local
local-filesystems/grouping astring require_all
local-filesystems/restart_on astring none
local-filesystems/type astring service
remote-filesystems/entities fmri svc:/network/nfs/client svc:/system/filesystem/autofs
remote-filesystems/grouping astring optional_all
remote-filesystems/restart_on astring none
remote-filesystems/type astring service
startd/duration astring transient
start/timeout_seconds count 0
start/type astring method
stop/exec astring :true
stop/timeout_seconds count 0
stop/type astring method
""",

                "svcprop_disabled" :
"""general/enabled boolean false
general/entity_stability astring Unstable
general/single_instance boolean true
restarter/start_pid count 4172
restarter/start_method_timestamp time 1222382991.639687000
restarter/start_method_waitstatus integer 0
restarter/transient_contract count
restarter/auxiliary_state astring none
restarter/next_state astring none
restarter/state astring disabled
restarter/state_timestamp time 1222992132.445811000
restarter_actions/refresh integer
restarter_actions/maint_on integer
restarter_actions/maint_off integer
restarter_actions/restart integer
local-filesystems/entities fmri svc:/system/filesystem/local
local-filesystems/grouping astring require_all
local-filesystems/restart_on astring none
local-filesystems/type astring service
remote-filesystems/entities fmri svc:/network/nfs/client svc:/system/filesystem/autofs
remote-filesystems/grouping astring optional_all
remote-filesystems/restart_on astring none
remote-filesystems/type astring service
startd/duration astring transient
start/timeout_seconds count 0
start/type astring method
stop/exec astring :true
stop/timeout_seconds count 0
stop/type astring method
""",

                "svcprop_temp_enabled" :
"""general/enabled boolean false
general/entity_stability astring Unstable
general/single_instance boolean true
restarter/start_pid count 7816
restarter/start_method_timestamp time 1222992237.506096000
restarter/start_method_waitstatus integer 0
restarter/transient_contract count
restarter/auxiliary_state astring none
restarter/next_state astring none
restarter/state astring online
restarter/state_timestamp time 1222992237.527408000
restarter_actions/refresh integer
restarter_actions/maint_on integer
restarter_actions/maint_off integer
restarter_actions/restart integer
general_ovr/enabled boolean true
local-filesystems/entities fmri svc:/system/filesystem/local
local-filesystems/grouping astring require_all
local-filesystems/restart_on astring none
local-filesystems/type astring service
remote-filesystems/entities fmri svc:/network/nfs/client svc:/system/filesystem/autofs
remote-filesystems/grouping astring optional_all
remote-filesystems/restart_on astring none
remote-filesystems/type astring service
startd/duration astring transient
start/timeout_seconds count 0
start/type astring method
stop/exec astring :true
stop/timeout_seconds count 0
stop/type astring method
""",
                "svcprop_temp_disabled" :
"""general/enabled boolean true
general/entity_stability astring Unstable
general/single_instance boolean true
restarter/start_pid count 7816
restarter/start_method_timestamp time 1222992237.506096000
restarter/start_method_waitstatus integer 0
restarter/transient_contract count
restarter/auxiliary_state astring none
restarter/next_state astring none
restarter/state astring disabled
restarter/state_timestamp time 1222992278.822335000
restarter_actions/refresh integer
restarter_actions/maint_on integer
restarter_actions/maint_off integer
restarter_actions/restart integer
general_ovr/enabled boolean false
local-filesystems/entities fmri svc:/system/filesystem/local
local-filesystems/grouping astring require_all
local-filesystems/restart_on astring none
local-filesystems/type astring service
remote-filesystems/entities fmri svc:/network/nfs/client svc:/system/filesystem/autofs
remote-filesystems/grouping astring optional_all
remote-filesystems/restart_on astring none
remote-filesystems/type astring service
startd/duration astring transient
start/timeout_seconds count 0
start/type astring method
stop/exec astring :true
stop/timeout_seconds count 0
stop/type astring method
""",

                "empty": "",
                "usr/bin/svcprop" :
"""#!/bin/sh
cat $PKG_TEST_DIR/$PKG_SVCPROP_OUTPUT
exit $PKG_SVCPROP_EXIT_CODE
""",
                "usr/sbin/svcadm" : \
"""#!/bin/sh
echo $0 "$@" >> $PKG_TEST_DIR/svcadm_arguments
exit $PKG_SVCADM_EXIT_CODE
"""
}

        testdata_dir = None

        def setUp(self):

                pkg5unittest.SingleDepotTestCase.setUp(self)
                self.testdata_dir = os.path.join(self.test_root, "testdata")
                os.mkdir(self.testdata_dir)

                self.pkg_list = []

                self.pkg_list+= ["""
                    open basics@1.0,5.11-0
                    add file testdata/empty mode=0644 owner=root group=sys path=/test_restart restart_fmri=svc:system/test_restart_svc
                    close """]

                self.pkg_list+= ["""
                    open basics@1.1,5.11-0
                    add file testdata/empty mode=0655 owner=root group=sys path=/test_restart restart_fmri=svc:system/test_restart_svc
                    close """]

                self.pkg_list+= ["""
                    open basics@1.2,5.11-0
                    add file testdata/empty mode=0646 owner=root group=sys path=/test_restart restart_fmri=svc:system/test_restart_svc
                    close """]

                self.pkg_list+= ["""
                    open basics@1.3,5.11-0
                    add file testdata/empty mode=0657 owner=root group=sys path=/test_restart refresh_fmri=svc:system/test_refresh_svc
                    close """]

                self.pkg_list+= ["""
                    open basics@1.4,5.11-0
                    add file testdata/empty mode=0667 owner=root group=sys path=/test_restart suspend_fmri=svc:system/test_suspend_svc
                    close """]

                self.pkg_list+= ["""
                    open basics@1.5,5.11-0
                    add file testdata/empty mode=0677 owner=root group=sys path=/test_restart suspend_fmri=svc:system/test_suspend_svc disable_fmri=svc:system/test_disable_svc
                    close """]

                self.make_misc_files(self.misc_files, prefix="testdata",
                     mode=0755)

        def test_actuators(self):
                """test actuators"""

                durl = self.dc.get_depot_url()
                for pkg in self.pkg_list:
                        self.pkgsend_bulk(durl, pkg)
                self.image_create(durl)
                os.environ["PKG_TEST_DIR"] = self.testdata_dir
                os.environ["PKG_SVCADM_EXIT_CODE"] = "0"
                os.environ["PKG_SVCPROP_EXIT_CODE"] = "0"

                svcadm_output = os.path.join(self.testdata_dir,
                    "svcadm_arguments")

                # make it look like our test service is enabled
                os.environ["PKG_SVCPROP_OUTPUT"] = "svcprop_enabled"

                # test to see if our test service is restarted on install
                cmdstr = "--debug actuator_cmds_dir=%s" % self.testdata_dir
                self.pkg(cmdstr + " install basics@1.0")
                self.pkg("verify")

                self.file_contains(svcadm_output, "svcadm restart svc:system/test_restart_svc")
                os.unlink(svcadm_output)

                # test to see if our test service is restarted on upgrade
                cmdstr = "--debug actuator_cmds_dir=%s" % self.testdata_dir
                self.pkg(cmdstr + " install basics@1.1")
                self.pkg("verify")
                self.file_contains(svcadm_output, "svcadm restart svc:system/test_restart_svc")
                os.unlink(svcadm_output)

                # test to see if our test service is restarted on uninstall
                self.pkg(cmdstr + " uninstall basics")
                self.pkg("verify")
                self.file_contains(svcadm_output, "svcadm restart svc:system/test_restart_svc")
                os.unlink(svcadm_output)

                # make it look like our test service is not enabled
                os.environ["PKG_SVCPROP_OUTPUT"] = "svcprop_disabled"

                # test to see to make sure we don't restart disabled service
                cmdstr = "--debug actuator_cmds_dir=%s" % self.testdata_dir
                self.pkg(cmdstr + " install basics@1.2")
                self.pkg("verify")
                self.file_does_not_exist(svcadm_output)

                # test to see if services that aren't installed are ignored
                os.environ["PKG_SVCPROP_EXIT_CODE"] = "1"
                self.pkg("uninstall basics")
                self.pkg("verify")
                cmdstr = "--debug actuator_cmds_dir=%s" % self.testdata_dir
                self.pkg(cmdstr + " install basics@1.2")
                self.pkg("verify")
                self.file_does_not_exist(svcadm_output)
                os.environ["PKG_SVCPROP_EXIT_CODE"] = "0"

                # make it look like our test service(s) is/are enabled
                os.environ["PKG_SVCPROP_OUTPUT"] = "svcprop_enabled"

                # test to see if refresh works as designed, along w/ restart
                cmdstr = "--debug actuator_cmds_dir=%s" % self.testdata_dir
                self.pkg(cmdstr + " install basics@1.3")
                self.pkg("verify")
                self.file_contains(svcadm_output, "svcadm restart svc:system/test_restart_svc")
                self.file_contains(svcadm_output, "svcadm refresh svc:system/test_refresh_svc")
                os.unlink(svcadm_output)

                # test if suspend works
                cmdstr = "--debug actuator_cmds_dir=%s" % self.testdata_dir
                self.pkg(cmdstr + " install basics@1.4")
                self.pkg("verify")
                self.file_contains(svcadm_output, "svcadm disable -st svc:system/test_suspend_svc")
                self.file_contains(svcadm_output, "svcadm enable svc:system/test_suspend_svc")
                os.unlink(svcadm_output)

                # test if suspend works properly w/ temp. enabled service
                # make it look like our test service(s) is/are temp enabled
                os.environ["PKG_SVCPROP_OUTPUT"] = "svcprop_temp_enabled"
                cmdstr = "--debug actuator_cmds_dir=%s" % self.testdata_dir
                self.pkg(cmdstr + " install basics@1.5")
                self.pkg("verify")
                self.file_contains(svcadm_output, "svcadm disable -st svc:system/test_suspend_svc")
                self.file_contains(svcadm_output, "svcadm enable -t svc:system/test_suspend_svc")
                os.unlink(svcadm_output)

                # test if service is disabled on uninstall
                cmdstr = "--debug actuator_cmds_dir=%s" % self.testdata_dir
                self.pkg(cmdstr + " uninstall basics")
                self.pkg("verify")
                self.file_contains(svcadm_output, "svcadm disable -s svc:system/test_disable_svc")

        def file_does_not_exist(self, path):
                file_path = os.path.join(self.get_img_path(), path)
                if os.path.exists(file_path):
                        self.assert_(False, "File %s exists" % path)

        def file_contains(self, path, string):
                file_path = os.path.join(self.get_img_path(), path)
                try:
                        f = file(file_path)
                except:
                        self.assert_(False, "File %s does not exist or contain %s" % (path, string))

                for line in f:
                        if string in line:
                                f.close()
                                break
                else:
                        f.close()
                        self.assert_(False, "File %s does not contain %s" % (path, string))

if __name__ == "__main__":
        unittest.main()
