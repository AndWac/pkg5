#!/usr/bin/python3.9
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

#
# Copyright (c) 2008, 2018, Oracle and/or its affiliates. All rights reserved.
#

"""module describing a user packaging object

This module contains the UserAction class, which represents a user
packaging object.  This contains the attributes necessary to create
a new user."""

from . import generic
try:
        from pkg.cfgfiles import *
        have_cfgfiles = True
except ImportError:
        have_cfgfiles = False

import pkg.client.api_errors as apx
import pkg.actions

class GroupAction(generic.Action):
        """Class representing a group packaging object.
        note that grouplist members are selected via the user action,
        although they are stored in the /etc/group file.  Use of
        group passwds is not supported."""

        __slots__ = []

        name = "group"
        key_attr = "groupname"
        globally_identical = True
        ordinality = generic._orderdict[name]

        def extract(self, attrlist):
                """ return a dictionary containing attrs in attr list
                from self.attrs; omit if no such attrs in self.attrs"""
                return dict((a, self.attrs[a])
                             for a in self.attrs
                             if a in attrlist)

        def install(self, pkgplan, orig, retry=False):
                """client-side method that adds the group
                   use gid from disk if different"""
                if not have_cfgfiles:
                        # the group action is ignored if cfgfiles is not
                        # available.
                        return

                template = self.extract(["groupname", "gid"])
                if "PKG_ACCOUNTS_DEBUG" in os.environ:
                        sys.stderr.write("[D] Processing group " + self.attrs["groupname"] + "\n")

                root = pkgplan.image.get_root()
                try:
                        pw = PasswordFile(root, lock=True)
                except EnvironmentError as e:
                        if e.errno != errno.ENOENT:
                                raise
                        pw = None

                gr = GroupFile(pkgplan.image)

                # Read group attrs from on-disk data, if any
                cur_attrs = gr.getvalue(template)

                # Check if the gid number is occupied
                if "gid" in self.attrs:
                        # ...if the pkg action required a gid number
                        cur_attrs_gid = gr.getgroupsbyid(self.attrs["gid"])
                        if cur_attrs_gid:
                                # ...if the GID definition(s) existed on-disk
                                # note there may be several aliases to same GID
                                if "PKG_ACCOUNTS_DEBUG" in os.environ:
                                        sys.stderr.write("[D] Group(s) with GID " + self.attrs["gid"] + ": " + str(cur_attrs_gid) + "\n")
                                may_proceed = False
                                existing_names = []
                                for cur_attrs_iter in cur_attrs_gid:
                                        if cur_attrs_iter["groupname"] == self.attrs["groupname"]:
                                                # At least one existing alias matches the group
                                                # we would create at the GID we require
                                                may_proceed = True
                                                # Of all possible aliases on this GID, this name
                                                # entry is the one we want to manage/update
                                                cur_attrs = cur_attrs_iter
                                        else:
                                                existing_names.append(cur_attrs_iter["groupname"])

                                if not may_proceed:
                                        # ...on-disk group name(s) all differ from
                                        # what we want to make now
                                        # TODO: want a 3-way check vs. orig(?) whether
                                        # the earlier package version we are upgrading
                                        # from delivered that other name, then we can
                                        # safely just rename it... or add an alias?..
                                        # Currently we safely bail and ask a human to
                                        # handle this "properly".
                                        if pw:
                                                pw.unlock()
                                        txt = _("Group named '{group}' cannot be installed. "
                                            "Requested GID number '{gid}' is already "
                                            "occupied by {groups}. "
                                            "Please evacuate that group to another ID "
                                            "first (including FS object ownership), or "
                                            "rename (or alias) the account to the new "
                                            "packaged name if applicable.").format(
                                                group=self.attrs["groupname"],
                                                gid=str(self.attrs["gid"]),
                                                groups=existing_names)
                                        if "PKG_ACCOUNTS_COLLISION" in os.environ and os.environ["PKG_ACCOUNTS_COLLISION"] == "permit":
                                                sys.stderr.write("WARNING (relaxed because PKG_ACCOUNTS_COLLISION==permit): " + txt + "\n")
                                        else:
                                                raise apx.ActionExecutionError(self,
                                                    details=txt,
                                                    fmri=pkgplan.destination_fmri)
                        if "PKG_ACCOUNTS_DEBUG" in os.environ:
                                sys.stderr.write("[D] GID " + self.attrs["gid"] + " is available or occupied by expected groupname\n")

                # check for (maybe wrong) pre-existing definition
                # if so, rewrite entry using existing defs but new group entry
                #        (XXX this doesn't chown any files on-disk)
                # else, nothing to do
                if cur_attrs:
                        # ...if the definition existed on-disk
                        if "gid" not in self.attrs:
                                # ...if the pkg action did not require a gid number
                                self.attrs["gid"] = cur_attrs["gid"]
                        elif self.attrs["gid"] != cur_attrs["gid"]:
                                # ...if the pkg action required a gid number and
                                # it differs from on-disk for same group name
                                cur_gid = cur_attrs["gid"]
                                template = cur_attrs;
                                template["gid"] = self.attrs["gid"]
                                # Update the user database with the new gid
                                # as well in case group is someone's primary
                                # group.
                                usernames = pkgplan.image.get_usernames_by_gid(
                                    cur_gid)
                                try:
                                        for username in usernames:
                                                user_entry = pw.getuser(
                                                        username)
                                                user_entry["gid"] = self.attrs[
                                                        "gid"]
                                                pw.setvalue(user_entry)
                                except Exception as e:
                                        if pw:
                                                pw.unlock()
                                                txt = _("Group cannot be installed. "
                                                        "Updating related user entries "
                                                        "failed.")
                                                raise apx.ActionExecutionError(self,
                                                    error=e, details=txt,
                                                    fmri=pkgplan.destination_fmri)

                        # Deal with other columns in the group row.
                        #
                        # pkg has no support for the legacy password field
                        # in the group table and thus requires it to be
                        # empty for any pkg delivered group.  So there is
                        # explicitly no support for updating
                        # template["password"] since we require it to be empty.
                        #
                        # If the admin has assigned any users to a group that is
                        # delivered as an action we preserve that list without
                        # attempting to validate it in any way.
                        if cur_attrs["user-list"]:
                            template["user-list"] = cur_attrs["user-list"]

                gr.setvalue(template)
                try:
                        gr.writefile()
                        if pw:
                                pw.writefile()
                except EnvironmentError as e:
                        if e.errno != errno.ENOENT:
                                raise
                        # If we're in the postinstall phase and the
                        # files *still* aren't there, bail gracefully.
                        if retry:
                                txt = _("Group cannot be installed "
                                    "without group database files "
                                    "present.")
                                raise apx.ActionExecutionError(self, error=e,
                                    details=txt, fmri=pkgplan.destination_fmri)
                        img = pkgplan.image
                        img._groups.add(self)
                        if "gid" in self.attrs:
                                img._groupsbyname[self.attrs["groupname"]] = \
                                    int(self.attrs["gid"])
                        raise pkg.actions.ActionRetry(self)
                finally:
                        if pw:
                                pw.unlock()

        def retry(self, pkgplan, orig):
                groups = pkgplan.image._groups
                if groups:
                        assert self in groups
                        self.install(pkgplan, orig, retry=True)

        def verify(self, img, **args):
                """Returns a tuple of lists of the form (errors, warnings,
                info).  The error list will be empty if the action has been
                correctly installed in the given image."""

                errors = []
                warnings = []
                info = []
                if not have_cfgfiles:
                        # The user action is ignored if cfgfiles is not
                        # available.
                        return errors, warnings, info

                gr = GroupFile(img)

                cur_attrs = gr.getvalue(self.attrs)

                # Get the default values if they're non-empty
                grdefval = dict((
                    (k, v)
                    for k, v in six.iteritems(gr.getdefaultvalues())
                    if v != ""
                ))

                # If "gid" is set dynamically, ignore what's on disk.
                if "gid" not in self.attrs:
                        cur_attrs["gid"] = ""

                should_be = grdefval.copy()
                should_be.update(self.attrs)
                # Note where attributes are missing
                for k in should_be:
                        cur_attrs.setdefault(k, "<missing>")
                # Note where attributes should be empty
                for k in cur_attrs:
                        if cur_attrs[k]:
                                should_be.setdefault(k, "<empty>")
                # Ignore "user-list", as it is only modified by user actions
                should_be.pop("user-list", None)

                errors = [
                    _("{entry}: '{found}' should be '{expected}'").format(
                        entry=a, found=cur_attrs[a],
                        expected=should_be[a])
                    for a in should_be
                    if cur_attrs[a] != should_be[a]
                ]
                return errors, warnings, info

        def remove(self, pkgplan):
                """client-side method that removes this group"""
                if not have_cfgfiles:
                        # The user action is ignored if cfgfiles is not
                        # available.
                        return
                gr = GroupFile(pkgplan.image)
                try:
                        gr.removevalue(self.attrs)
                except KeyError as e:
                        # Already gone; don't care.
                        pass
                else:
                        gr.writefile()

        def generate_indices(self):
                """Generates the indices needed by the search dictionary.  See
                generic.py for a more detailed explanation."""

                return [("group", "name", self.attrs["groupname"], None)]

        def validate(self, fmri=None):
                """Performs additional validation of action attributes that
                for performance or other reasons cannot or should not be done
                during Action object creation.  An ActionError exception (or
                subclass of) will be raised if any attributes are not valid.
                This is primarily intended for use during publication or during
                error handling to provide additional diagonostics.

                'fmri' is an optional package FMRI (object or string) indicating
                what package contained this action.
                """

                generic.Action._validate(self, fmri=fmri,
                    numeric_attrs=("gid",), single_attrs=("gid",))

        def compare(self, other):
                """Arrange for group actions to be installed in gid order.  This
                will only hold true for actions installed at one time, but that's
                generally what we need on initial install."""
                # put unspecifed gids at the end
                a = int(self.attrs.get("gid", 1024))
                b = int(other.attrs.get("gid", 1024))
                return (a > b) - (a < b)

# Vim hints
# vim:ts=8:sw=8:et:fdm=marker
