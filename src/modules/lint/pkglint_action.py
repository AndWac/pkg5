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

#
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

from pkg.lint.engine import lint_fmri_successor

import collections
import pkg.fmri
import pkg.lint.base as base
import stat
import string

ObsoleteFmri = collections.namedtuple("ObsoleteFmri", "is_obsolete, fmri")

class PkgDupActionChecker(base.ActionChecker):
        """A class to check duplicate actions/attributes."""

        name = "pkglint.dupaction"

        def __init__(self, config):
                # dictionaries mapping path names to a list of tuples that are
                # installing to that path name. Each tuple represents a single
                # action and the fmri that delivers that action, to allow for a
                # given fmri delivering multiple copies of actions that install
                # to that path.
                # eg. pathdb[path] = [(fmri, action), (fmri, action) ... ]

                # The paths dictionaries for large repositories are rather
                # memory hungry and may well be useful services for other
                # checkers, so could be rolled into the engine itself (at the
                # cost of all checker classes paying the toll on engine
                # startup time.
                # We maintain similar dictionaries for other attributes that
                # should not be duplicated across (and within) manifests.

                self.description = _("Checks for duplicate IPS actions.")

                self.ref_paths = {}
                self.lint_paths = {}

                # similar dictionaries for drivers
                self.ref_drivers = {}
                self.lint_drivers = {}

                # and users / groups
                self.ref_usernames = {}
                self.ref_uids = {}
                self.lint_usernames = {}
                self.lint_uids = {}

                self.ref_groupnames = {}
                self.lint_groupnames = {}

                self.ref_gids = {}
                self.lint_gids = {}

                self.processed_paths = {}
                self.processed_drivers = {}
                self.processed_paths = {}
                self.processed_usernames = {}
                self.processed_uids = {}
                self.processed_groupnames = {}
                self.processed_gids = {}

                self.processed_refcount_paths = {}

                # mark which paths we've done duplicate-type checking on
                self.seen_dup_types = {}

                self.refcounted_actions = [ "dir", "hardlink", "link" ]
                super(PkgDupActionChecker, self).__init__(config)

        def startup(self, engine):
                """Called to initialise a given checker using the supplied
                    engine."""

                def seed_dict(mf, attr, dic, atype=None, verbose=False):
                        """Updates a dictionary of { attr: [(fmri, action), ..]}
                        where attr is the value of that attribute from
                        actions of a given type atype, in the given
                        manifest."""

                        pkg_vars = mf.get_all_variants()

                        def mf_gen(atype):
                                if atype:
                                        for a in mf.gen_actions_by_type(atype):
                                                yield a
                                else:
                                        for a in mf.gen_actions():
                                                yield a

                        for action in mf_gen(atype):
                                if atype and action.name != atype:
                                        continue
                                if attr not in action.attrs:
                                        continue
                                if "pkg.linted" in action.attrs and \
                                    action.attrs["pkg.linted"].lower() == "true":
                                        continue

                                variants = action.get_variant_template()
                                variants.merge_unknown(pkg_vars)
                                action.attrs.update(variants)

                                p = action.attrs[attr]
                                if p not in dic:
                                        dic[p] = [(mf.fmri, action)]
                                else:
                                        dic[p].append((mf.fmri, action))

                engine.logger.debug(
                    _("Seeding reference action duplicates dictionaries."))

                for manifest in engine.gen_manifests(engine.ref_api_inst,
                    release=engine.release):
                        seed_dict(manifest, "path", self.ref_paths)
                        seed_dict(manifest, "name", self.ref_drivers,
                            atype="driver")
                        seed_dict(manifest, "username", self.ref_usernames,
                            atype="user")
                        seed_dict(manifest, "uid", self.ref_uids,
                            atype="user")
                        seed_dict(manifest, "groupname", self.ref_groupnames,
                            atype="group")
                        seed_dict(manifest, "gid", self.ref_gids, atype="group")

                engine.logger.debug(
                    _("Seeding lint action duplicates dictionaries."))

                # we provide a search pattern, to allow users to lint a
                # subset of the packages in the lint_repository
                for manifest in engine.gen_manifests(engine.lint_api_inst,
                    release=engine.release, pattern=engine.pattern):
                        seed_dict(manifest, "path", self.lint_paths)
                        seed_dict(manifest, "name", self.lint_drivers,
                            atype="driver")
                        seed_dict(manifest, "username", self.lint_usernames,
                            atype="user")
                        seed_dict(manifest, "uid", self.lint_uids, atype="user")
                        seed_dict(manifest, "groupname", self.lint_groupnames,
                            atype="group")
                        seed_dict(manifest, "gid", self.lint_gids,
                            atype="group")

                engine.logger.debug(
                    _("Seeding local action duplicates dictionaries."))

                for manifest in engine.lint_manifests:
                        seed_dict(manifest, "path", self.lint_paths)
                        seed_dict(manifest, "name", self.lint_drivers,
                            atype="driver")
                        seed_dict(manifest, "username", self.lint_usernames,
                            atype="user")
                        seed_dict(manifest, "uid", self.lint_uids, atype="user")
                        seed_dict(manifest, "groupname", self.lint_groupnames,
                            atype="group")
                        seed_dict(manifest, "gid", self.lint_gids,
                            atype="group")

                dup_dictionaries = [(self.lint_paths, self.ref_paths),
                    (self.lint_drivers, self.ref_drivers),
                    (self.lint_usernames, self.ref_usernames),
                    (self.lint_uids, self.ref_uids),
                    (self.lint_groupnames, self.ref_groupnames),
                    (self.lint_gids, self.ref_gids)]

                for lint_dic, ref_dic in dup_dictionaries:
                        self._merge_dict(lint_dic, ref_dic,
                            ignore_pubs=engine.ignore_pubs)
                        self.lint_dic = {}

        def duplicate_paths(self, action, manifest, engine, pkglint_id="001"):
                """Checks for duplicate paths on non-ref-counted actions."""

                self.dup_attr_check(["file", "license"], "path", self.ref_paths,
                    self.processed_paths, action, engine,
                    manifest.get_all_variants(), msgid=pkglint_id)

        duplicate_paths.pkglint_desc = _(
            "Paths should be unique.")

        def duplicate_drivers(self, action, manifest, engine, pkglint_id="002"):
                """Checks for duplicate driver names."""

                self.dup_attr_check(["driver"], "name", self.ref_drivers,
                    self.processed_drivers, action, engine,
                    manifest.get_all_variants(), msgid=pkglint_id)

        duplicate_drivers.pkglint_desc = _("Driver names should be unique.")

        def duplicate_usernames(self, action, manifest, engine,
            pkglint_id="003"):
                """Checks for duplicate user names."""

                self.dup_attr_check(["user"], "username", self.ref_usernames,
                    self.processed_usernames, action, engine,
                    manifest.get_all_variants(), msgid=pkglint_id)

        duplicate_usernames.pkglint_desc = _("User names should be unique.")

        def duplicate_uids(self, action, manifest, engine, pkglint_id="004"):
                """Checks for duplicate uids."""

                self.dup_attr_check(["user"], "uid", self.ref_uids,
                    self.processed_uids, action, engine,
                    manifest.get_all_variants(), msgid=pkglint_id)

        duplicate_uids.pkglint_desc = _("UIDs should be unique.")

        def duplicate_groupnames(self, action, manifest, engine,
            pkglint_id="005"):
                """Checks for duplicate group names."""

                self.dup_attr_check(["group"], "groupname", self.ref_groupnames,
                    self.processed_groupnames, action, engine,
                    manifest.get_all_variants(), msgid=pkglint_id)

        duplicate_groupnames.pkglint_desc = _(
            "Group names should be unique.")

        def duplicate_gids(self, action, manifest, engine, pkglint_id="006"):
                """Checks for duplicate gids."""

                self.dup_attr_check(["group"], "name", self.ref_gids,
                    self.processed_gids, action, engine,
                    manifest.get_all_variants(), msgid=pkglint_id)

        duplicate_gids.pkglint_desc = _("GIDs should be unique.")

        def duplicate_refcount_path_attrs(self, action, manifest, engine,
            pkglint_id="007"):
                """Checks that for duplicated reference-counted actions,
                all attributes in those duplicates are the same."""

                if "path" not in action.attrs:
                        return
                if action.name not in self.refcounted_actions:
                        return
                p = action.attrs["path"]

                if p in self.ref_paths and len(self.ref_paths[p]) == 1:
                        return

                if p in self.processed_refcount_paths:
                        return

                fmris = set()
                target = action
                differences = set()
                for (pfmri, a) in self.ref_paths[p]:
                        fmris.add(pfmri)
                        for key in a.differences(target):
                                # target, used in link actions often differs
                                # between variants of those actions.
                                if key.startswith("variant") or \
                                    key.startswith("facet") or \
                                    key.startswith("target"):
                                        continue
                                conflicting_vars, variants = \
                                    self.conflicting_variants([a, target],
                                        manifest.get_all_variants())
                                if not conflicting_vars:
                                        continue
                                differences.add(key)
                suspects = []
                if differences:
                        for key in sorted(differences):
                                # a dictionary to map unique values for this key
                                # the fmris that deliver them
                                attr = {}
                                for (pfmri, a) in self.ref_paths[p]:
                                        if key in a.attrs:
                                                val = a.attrs[key]
                                                if val in attr:
                                                        attr[val].append(pfmri)
                                                else:
                                                        attr[val] = [pfmri]
                                for val in sorted(attr):
                                        suspects.append("%s: %s -> %s" %
                                            (key, val,
                                            " ".join([pfmri.get_name()
                                            for pfmri in sorted(attr[val])
                                            ])))
                        engine.error(_("path %(path)s is reference-counted "
                            "but has different attributes across %(count)s "
                            "duplicates: %(suspects)s") %
                            {"path": p,
                            "count": len(fmris) + 1,
                            "suspects": " ".join([key for key in suspects])},
                            msgid="%s%s" % (self.name, pkglint_id))
                self.processed_refcount_paths[p] = True

        duplicate_refcount_path_attrs.pkglint_desc = _(
            "Duplicated reference counted actions should have the same attrs.")

        def dup_attr_check(self, action_names, attr_name, ref_dic,
            processed_dic, action, engine, pkg_vars, msgid=""):
                """This method does generic duplicate action checking where
                we know the type of action and name of an action attributes
                across actions/manifests that should not be duplicated.

                'action_names' A list of the type of actions to check

                'attr_name' The attribute name we're checking

                'ref_dic' Built in setup() this dictionary maps attr_name values
                to a list of all (fmri, action) tuples that deliver that
                attr_name value.

                'processed_dic' Records whether we've already called this method
                for a given attr_name value

                'action' The current action we're checking

                'engine' The LintEngine calling this method

                'id' The pkglint_id to use when logging messages."""

                if attr_name not in action.attrs:
                        return

                if action.name not in action_names:
                        return

                name = action.attrs[attr_name]

                if name in processed_dic:
                        return

                if name in ref_dic and len(ref_dic[name]) == 1:
                        return

                fmris = set()
                actions = set()
                for (pfmri, a) in ref_dic[name]:
                        actions.add(a)
                        fmris.add(pfmri)

                has_conflict, conflict_vars = self.conflicting_variants(actions,
                    pkg_vars)
                if has_conflict:
                        plist = [f.get_fmri() for f in sorted(fmris)]
                        if not conflict_vars:
                                engine.error(_("%(attr_name)s %(name)s is "
                                    "a duplicate delivered by %(pkgs)s "
                                    "under all variant combinations") %
                                    {"attr_name": attr_name,
                                    "name": name,
                                    "pkgs": " ".join(plist)},
                                    msgid="%s%s.1" % (self.name, msgid))
                        else:
                                for fz in conflict_vars:
                                        engine.error(_("%(attr_name)s %(name)s "
                                            "is a duplicate delivered by "
                                            "%(pkgs)s declaring overlapping "
                                            "variants %(vars)s") %
                                            {"attr_name": attr_name,
                                            "name": name,
                                            "pkgs": " ".join(plist),
                                            "vars":
                                            " ".join(["%s=%s" % (k, v)
                                                for (k, v)
                                                in sorted(fz)])},
                                            msgid="%s%s.2" % (self.name, msgid))
                processed_dic[name] = True

        def duplicate_path_types(self, action, manifest, engine,
            pkglint_id="008"):
                """Checks to see if the action containing a path attribute
                has that action delivered by multiple action types."""

                if "path" not in action.attrs:
                        return

                p = action.attrs["path"]

                if p in self.seen_dup_types:
                        return

                types = set()
                fmris = set()
                actions = set()
                for (pfmri, a) in self.ref_paths[p]:
                        actions.add(a)
                        types.add(a.name)
                        fmris.add(pfmri)
                if len(types) > 1:
                        has_conflict, conflict_vars = \
                            self.conflicting_variants(actions,
                                manifest.get_all_variants())
                        if has_conflict:
                                plist = [f.get_fmri() for f in sorted(fmris)]
                                plist.sort()
                                engine.error(
                                    _("path %(path)s is delivered by multiple "
                                    "action types across %(pkgs)s") %
                                    {"path": p,
                                    "pkgs":
                                    " ".join(plist)},
                                    msgid="%s%s" % (self.name, pkglint_id))
                self.seen_dup_types[p] = True

        duplicate_path_types.pkglint_desc = _(
            "Paths should be delivered by one action type only.")

        def _merge_dict(self, src, target, ignore_pubs=True):
                """Merges the given src dictionary into the target
                dictionary, giving us the target content as it would appear,
                were the packages in src to get published to the
                repositories that made up target.

                We need to only merge packages at the same or successive
                version from the src dictionary into the target dictionary.
                If the src dictionary contains a package with no version
                information, it is assumed to be more recent than the same
                package with no version in the target."""

                for p in src:
                        if p not in target:
                                target[p] = src[p]
                                continue

                        def build_dic(arr):
                                """Builds a dictionary of fmri:action entries"""
                                dic = {}
                                for (pfmri, action) in arr:
                                        if pfmri in dic:
                                                dic[pfmri].append(action)
                                        else:
                                                dic[pfmri] = [action]
                                return dic

                        src_dic = build_dic(src[p])
                        targ_dic = build_dic(target[p])

                        for src_pfmri in src_dic:
                                # we want to remove entries deemed older than
                                # src_pfmri from targ_dic.
                                for targ_pfmri in targ_dic.copy():
                                        sname = src_pfmri.get_name()
                                        tname = targ_pfmri.get_name()
                                        if lint_fmri_successor(src_pfmri,
                                            targ_pfmri,
                                            ignore_pubs=ignore_pubs):
                                                targ_dic.pop(targ_pfmri)
                        targ_dic.update(src_dic)
                        l = []
                        for pfmri in targ_dic:
                                for action in targ_dic[pfmri]:
                                        l.append((pfmri, action))
                        target[p] = l


class PkgActionChecker(base.ActionChecker):

        name = "pkglint.action"

        def __init__(self, config):
                self.description = _("Various checks on actions")

                # a list of fmris which were declared as dependencies, but
                # which we weren't able to locate a manifest for.
                self.missing_deps = []

                # maps package names to tuples of (obsolete, fmri) values where
                # 'obsolete' is a boolean, True if the package is obsolete
                self.obsolete_pkgs = {}
                super(PkgActionChecker, self).__init__(config)

        def startup(self, engine):
                """Cache all manifest FMRIs, tracking whether they're
                obsolete or not."""


                def seed_obsolete_dict(mf, dic):
                        """Updates a dictionary of { pkg_name: ObsoleteFmri }
                        items, tracking which were marked as obsolete."""

                        name = mf.fmri.get_name()

                        if "pkg.obsolete" in mf and \
                            mf["pkg.obsolete"].lower() == "true":
                                dic[name] = ObsoleteFmri(True, mf.fmri)
                        elif "pkg.renamed" not in mf or \
                            mf["pkg.renamed"].lower() == "false":
                                # we can't yet tell if a renamed
                                # package gets obsoleted further down
                                # its rename chain, so don't decide now
                                dic[name] = ObsoleteFmri(False, mf.fmri)

                engine.logger.debug(_("Seeding reference action dictionaries."))
                for manifest in engine.gen_manifests(engine.ref_api_inst,
                    release=engine.release):
                        seed_obsolete_dict(manifest, self.obsolete_pkgs)

                engine.logger.debug(_("Seeding lint action dictionaries."))
                # we provide a search pattern, to allow users to lint a
                # subset of the packages in the lint_repository
                for manifest in engine.gen_manifests(engine.lint_api_inst,
                    release=engine.release, pattern=engine.pattern):
                        seed_obsolete_dict(manifest, self.obsolete_pkgs)

                engine.logger.debug(_("Seeding local action dictionaries."))
                for manifest in engine.lint_manifests:
                        seed_obsolete_dict(manifest, self.obsolete_pkgs)

        def underscores(self, action, manifest, engine, pkglint_id="001"):
                """In general, pkg(5) discourages the use of underscores in
                attributes."""

                for key in action.attrs.keys():
                        if "_" in key:
                                if key in ["original_name", "refresh_fmri",
                                    "restart_fmri", "suspend_fmri",
                                    "disable_fmri", "clone_perms",
                                    "reboot_needed"] or \
                                        key.startswith("facet.locale."):
                                        continue
                                engine.warning(
                                    _("underscore in attribute name %(key)s in "
                                    "%(fmri)s") %
                                    {"key": key,
                                    "fmri": manifest.fmri},
                                    msgid="%s%s" % (self.name, pkglint_id))

                if action.name != "set":
                        return

                name = action.attrs["name"]

                if "_" not in name or name in ["info.maintainer_url",
                    "info.upstream_url", "info.source_url",
                    "info.repository_url", "info.repository_changeset",
                    "info.defect_tracker.url", "opensolaris.arc_url"]:
                            return

                engine.warning(_("underscore in 'set' action name %(name)s in "
                    "%(fmri)s") % {"name": name,
                    "fmri": manifest.fmri},
                    msgid="%s%s.2" % (self.name, pkglint_id))

        underscores.pkglint_desc = _(
            "Underscores are discouraged in action attributes.")

        def unusual_perms(self, action, manifest, engine, pkglint_id="002"):
                """Checks that the permissions in this action look sane."""

                if "mode" in action.attrs:
                        mode = action.attrs["mode"]
                        path = action.attrs["path"]
                        st = None
                        try:
                                st = stat.S_IMODE(string.atoi(mode, 8))
                        except ValueError:
                                pass

                        if action.name == "dir":
                                # check for at least one executable bit
                                if st and \
                                    (stat.S_IXUSR & st or stat.S_IXGRP & st
                                    or stat.S_IXOTH & st):
                                        pass
                                elif st:
                                        engine.warning(_("directory action for "
                                            "%(path)s delivered in %(pkg)s with "
                                            "mode=%(mode)s "
                                            "that has no executable bits") %
                                            {"path": path,
                                            "pkg": manifest.fmri,
                                            "mode": mode},
                                            msgid="%s%s.1" %
                                            (self.name, pkglint_id))

                        if not st:
                                engine.error(_("broken mode mode=%(mode)s "
                                    "delivered in action for %(path)s in "
                                    "%(pkg)s") %
                                    {"path": path,
                                    "pkg": manifest.fmri,
                                    "mode": mode},
                                    msgid="%s%s.2" % (self.name, pkglint_id))

                        if len(mode) < 3:
                                engine.error(_("mode=%(mode)s is too short in "
                                    "action for %(path)s in %(pkg)s") %
                                    {"path": path,
                                    "pkg": manifest.fmri,
                                    "mode": mode},
                                    msgid="%s%s.3" % (self.name, pkglint_id))
                                return

                        # now check for individual access permissions
                        user = mode[-3]
                        group = mode[-2]
                        other = mode[-1]

                        if (other > group or
                            group > user or
                            other > user):
                                engine.warning(_("unusual mode mode=%(mode)s "
                                    "delivered in action for %(path)s in "
                                    "%(pkg)s") %
                                    {"path": path,
                                    "pkg": manifest.fmri,
                                    "mode": mode},
                                    msgid="%s%s.4" % (self.name, pkglint_id))

        def legacy(self, action, manifest, engine, pkglint_id="003"):
                """Cross-check that the 'pkg' attribute points to a package
                that depends on the package containing this legacy action.
                Also check that all the required tags are present on this
                legacy action."""

                if action.name != "legacy":
                        return

                name = manifest.fmri.get_name()

                for required in [ "category", "desc", "hotline", "name",
                    "pkg", "vendor", "version" ]:
                            if required not in action.attrs:
                                    engine.error(
                                        _("%(attr)s missing from legacy "
                                        "action in %(pkg)s") %
                                        {"attr": required,
                                        "pkg": manifest.fmri},
                                        msgid="%s%s.1" %
                                        (self.name, pkglint_id))

                if "pkg" in action.attrs:

                        legacy = engine.get_manifest(action.attrs["pkg"],
                            search_type=engine.LATEST_SUCCESSOR)
                        # Some legacy ancestor packages never existed as pkg(5)
                        # stubs
                        if legacy:
                                self.check_legacy_rename(legacy, action,
                                    manifest, engine, pkglint_id)

                if "version" in action.attrs:
                        # this could be refined
                        if "REV=" not in action.attrs["version"]:
                                engine.warning(
                                    _("legacy action in %s does not "
                                    "contain a REV= string") % manifest.fmri,
                                    msgid="%s%s.3" % (self.name, pkglint_id))

        def check_legacy_rename(self, legacy, action, manifest, engine,
            lint_id):
                """Part of the legacy(..) check, not an individual check,
                determines that the renaming of a package manifest, "legacy",
                referred to by a legacy action, "action", was done correctly
                and ultimately results on a dependency on the package,
                "manifest"."""

                if "pkg.renamed" in legacy and \
                    legacy["pkg.renamed"].lower() == "true":
                        mf = None
                        try:
                                mf = engine.follow_renames(action.attrs["pkg"],
                                    target=manifest.fmri, old_mfs=[])
                        except base.LintException, e:
                                # we've tried to rename to ourselves
                                engine.error(_("legacy renaming: %s") % str(e),
                                    msgid="%s%s.5" % (self.name, lint_id))
                                return

                        if mf is None:
                                engine.error(_("legacy package %(legacy)s did "
                                    "not result in a dependency on %(pkg)s when"
                                    " following package renames") %
                                    {"legacy": legacy.fmri,
                                    "pkg": manifest.fmri},
                                    msgid="%s%s.4" %
                                    (self.name, lint_id))

                        elif not lint_fmri_successor(manifest.fmri, mf.fmri,
                            ignore_pubs=engine.ignore_pubs):
                                engine.error(_("legacy package %(legacy)s did "
                                    "not result in a dependency on %(pkg)s") %
                                    {"legacy": legacy.fmri,
                                    "pkg": manifest.fmri},
                                    msgid="%s%s.2" %
                                    (self.name, lint_id))

        legacy.pkglint_desc = _(
            "'legacy' actions should have valid attributes.")

        def unknown(self, action, manifest, engine, pkglint_id="004"):
                """We should never have actions called 'unknown'."""

                if action.name is "unknown":
                        engine.error(_("unknown action found in %s") %
                            manifest.fmri,
                            msgid="%s%s" % (self.name, pkglint_id))

        unknown.pkglint_desc = _("'unknown' actions should never occur.")

        def dep_obsolete(self, action, manifest, engine, pkglint_id="005"):
                """We should not have a require dependency on a package that has
                been marked as obsolete.

                This check also produces warnings when it is unable to find
                manifests marked as dependencies for a given package in order
                to check for their obsoletion.  This can help to detect errors
                in the fmri attribute field of the depend action, though can be
                noisy if all dependencies are intentionally not present in the
                repository being linted or referenced."""

                msg = _("dependency on obsolete package in %s:")

                if action.name != "depend":
                        return

                if action.attrs["type"] != "require":
                        return

                # it's ok for renamed packages to eventually be obsoleted
                if "pkg.renamed" in manifest and \
                    manifest["pkg.renamed"].lower() == "true":
                        return

                name = None
                declared_fmri = None
                dep_fmri = action.attrs["fmri"]

                # normalize the fmri
                if not dep_fmri.startswith("pkg:/"):
                        dep_fmri = "pkg:/%s" % dep_fmri

                try:
                        declared_fmri = pkg.fmri.PkgFmri(dep_fmri)
                        name = declared_fmri.get_name()
                except pkg.fmri.IllegalFmri:
                        try:
                                declared_fmri = pkg.fmri.PkgFmri(dep_fmri,
                                    build_release="5.11")
                                name = declared_fmri.get_name()
                        except:
                                # A very broken fmri value - we'll give up now.
                                # valid_fmri() will pick up the trail from here.
                                return

                # if we've been unable to find a dependency for a given
                # fmri in the past, no need to keep complaining about it
                if dep_fmri in self.missing_deps:
                        return

                # There's a good chance that dependencies can be satisfied from
                # the manifests we cached during startup() Check there first.
                if name and name in self.obsolete_pkgs:

                        if not self.obsolete_pkgs[name].is_obsolete:
                                # the cached package is not obsolete, but we'll
                                # verify the version is valid
                                found_fmri = self.obsolete_pkgs[name].fmri
                                if not declared_fmri.has_version():
                                        return
                                elif lint_fmri_successor(found_fmri,
                                    declared_fmri,
                                    ignore_pubs=engine.ignore_pubs):
                                        return

                # A non-obsolete dependency wasn't found in the local cache,
                # or the one in the cache was found not to be a successor of
                # the fmri in the depend action.
                lint_id = "%s%s" % (self.name, pkglint_id)

                mf = None
                found_obsolete = False
                try:
                        mf = engine.follow_renames(
                            dep_fmri, old_mfs=[], warn_on_obsolete=True)
                except base.LintException, err:
                        found_obsolete = True
                        engine.error("%s %s" % (msg % manifest.fmri, err),
                            msgid=lint_id)

                if not mf and not found_obsolete:
                        self.missing_deps.append(dep_fmri)
                        engine.warning(_("obsolete dependency check "
                            "skipped: unable to find dependency %(dep)s"
                            " for %(pkg)s") %
                            {"dep": dep_fmri,
                            "pkg": manifest.fmri},
                            msgid="%s.1" % lint_id)

        dep_obsolete.pkglint_desc = _(
            "Packages should not have dependencies on obsolete packages.")

        def valid_fmri(self, action, manifest, engine, pkglint_id="006"):
                """We should be given a valid FMRI as a dependency, allowing
                for a potentially missing component value"""

                if "fmri" not in action.attrs:
                        return
                try:
                        pfmri = pkg.fmri.PkgFmri(action.attrs["fmri"])
                except pkg.fmri.IllegalFmri:
                        # we also need to just verify that the fmri isn't
                        # just missing a build_release value
                        try:
                                pfmri = pkg.fmri.PkgFmri(action.attrs["fmri"],
                                    build_release="5.11")
                        except pkg.fmri.IllegalFmri:
                                engine.error("invalid FMRI in action %(action)s"
                                    " in %(pkg)s" %
                                    {"pkg": manifest.fmri,
                                    "action": action},
                                    msgid="%s%s" % (self.name, pkglint_id))

        valid_fmri.pkglint_desc = _("pkg(5) FMRIs should be valid.")

        def license(self, action, manifest, engine, pkglint_id="007"):
                """License actions should not have path attributes."""

                if action.name is "license" and "path" in action.attrs:
                        engine.error(
                            _("license action in %(pkg)s has a path attribute, "
                            "%(path)s") %
                            {"pkg": manifest.fmri,
                            "path": action.attrs["path"]},
                            msgid="%s%s" % (self.name, pkglint_id))

        license.pkglint_desc = _("'license' actions should not have paths.")
