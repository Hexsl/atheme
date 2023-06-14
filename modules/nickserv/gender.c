/** Original code: https://gist.github.com/alexwilson/95cbb8ad0f7969a6387571e51bc8bbfb
 * Copyright (c) 2017 Alex Wilson <a@ax.gy>
 * New code:
 * Copyright (c) Kufat <kufat@kufat.net>
 * V2 Updates:
 * Copyright (c) 2023 Hexick <me@hexick.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 **/

/*
 * Sets and displays gender identity info within a user's /WHOIS and /NS INFO output.
 */

#include <atheme.h>

const char *const bannedWords[] = {"apache", "attack", "helicopter"};
int bannedWordCount = sizeof(bannedWords) / sizeof(bannedWords[0]);

static void ircd_send_meta(stringref *uid, char *gender) {
    if (PROTOCOL_INSPIRCD == ircd->type) {
        slog(LG_VERBOSE, ":%s METADATA %s %s :%s", me.numeric, uid, "gender", gender);
        sts(":%s METADATA %s %s :%s", me.numeric, uid, "gender", gender);
    }
}

static void user_info_hook(struct hook_user_req *hdata) {
    struct metadata *md;

    if (md = metadata_find(hdata->mu, "private:gender")) {
        (void) command_success_nodata(hdata->si, _("\2%s\2 identifies as: %s"),
                                      entity(hdata->mu)->name,
                                      md->value);
    }
}

static void user_identify_hook(struct user *u) {
    struct metadata *md;

    if (!u) { // This should never happen.
        return;
    }
    if ((md = metadata_find(u->myuser, "private:gender"))) {
        (void) ircd_send_meta(u->uid, md->value);
    }
}

static void ns_cmd_gender(struct sourceinfo *const restrict si, const int ATHEME_VATTR_UNUSED parc, char *parv[]) {
    char *gender = parv[0];
    struct metadata *md;

    if (!gender) {
        md = metadata_find(si->smu, "private:gender");

        if (!md) {
            (void) command_fail(si, fault_nochange, _("Your gender was already cleared."));

            return;
        }

        (void) metadata_delete(si->smu, "private:gender");
        (void) logcommand(si, CMDLOG_SET, "GENDER:REMOVE");
        for (int i = 0; i < bannedWordCount; ++i) {
            if (si->su) {
                (void) ircd_send_meta(si->su->uid, "");
            }
        }

        return;
    }

    for (int i = 0; i < bannedWordCount; ++i) {
        char *found = strcasestr(gender, bannedWords[i]);

        if (found) {
            (void) command_fail(si,
                                fault_badparams,
                                _("The word '%s' is on the banned words list for %s."),
                                bannedWords[i],
                                "GENDER");
            (void) logcommand(si, CMDLOG_SET, "GENDER: Troll gender \2%s\2", gender);
            (void) kill_user(si->service->me, si->su, "%s", "User attempted to set a gender containing a word on the disallow list.");

            return;
        }
    }

    (void) metadata_add(si->smu, "private:gender", gender);
    (void) logcommand(si, CMDLOG_SET, "GENDER: \2%s\2", gender);
    if (si->su) {
        (void) ircd_send_meta(si->su->uid, gender);
    }

    (void) command_success_nodata(si, _("Your gender is now set to \2%s\2."), gender);
}

static struct command ns_gender = {
        .name = "GENDER",
        .desc = N_("Set gender identity info."),
        .access = AC_AUTHENTICATED,
        .maxparc = 1,
        .cmd = &ns_cmd_gender,
        .help = {.path = "nickserv/gender"},
};

static void mod_init(struct module *const restrict m) {
    struct user *u;
    mowgli_patricia_iteration_state_t state;

    (void) hook_add_user_info(user_info_hook);
    (void) hook_add_user_identify(user_identify_hook);

    MODULE_TRY_REQUEST_DEPENDENCY(m, "nickserv/main")

    (void) service_named_bind_command("nickserv", &ns_gender);

    MOWGLI_PATRICIA_FOREACH(u, &state, userlist) {
        struct metadata *md;

        if (u->myuser && (md = metadata_find(u->myuser, "private:gender"))) {
            ircd_send_meta(u->uid, md->value);
        }
    }
}

static void mod_deinit(const enum module_unload_intent ATHEME_VATTR_UNUSED intent) {
    (void) hook_del_user_info(user_info_hook);
    (void) hook_del_user_identify(user_identify_hook);

    (void) service_named_unbind_command("nickserv", &ns_gender);
}

SIMPLE_DECLARE_MODULE_V1("nickserv/gender", MODULE_UNLOAD_CAPABILITY_OK)
