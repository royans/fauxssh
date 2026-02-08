import asyncio
import logging
import uuid
from datetime import datetime
import json
import os


from ssh_honeypot.core.config import config
from ssh_honeypot.core.database import HoneyDB

log = logging.getLogger("ssh_honeypot.imap.session")


class ImapState:
    NOT_AUTHENTICATED = "NOT_AUTHENTICATED"
    AUTHENTICATED = "AUTHENTICATED"
    SELECTED = "SELECTED"
    LOGOUT = "LOGOUT"


class ImapSession:
    def __init__(self, transport, db_instance, llm_instance):
        self.transport = transport
        self.db = db_instance
        self.llm = llm_instance
        self.session_id = str(uuid.uuid4())
        self.remote_ip, self.remote_port = transport.get_extra_info("peername")
        self.state = ImapState.NOT_AUTHENTICATED
        self.user = None
        self.selected_mailbox = None
        self.secure = False
        self.start_time = datetime.now()

        # Identity mapping for VFS-style persistence
        self.identity_ip = self.remote_ip
        self.identity_user = None

    def _generate_initial_emails(self):
        log.info(f"[IMAP] Generating initial emails for {self.user} ({self.remote_ip})")

        # Load persona data if available
        persona_name = config.get("persona", "name") or "CentOS7_Legacy_Compute"
        persona_dir = os.path.join("personas", persona_name)
        inbox_yaml = os.path.join(persona_dir, "imap", "inbox.yaml")

        emails = []
        if os.path.exists(inbox_yaml):
            try:
                import yaml

                with open(inbox_yaml, "r") as f:
                    emails = yaml.safe_load(f)
                log.info(f"[IMAP] Loaded {len(emails)} emails from {inbox_yaml}")
            except Exception as e:
                log.error(f"[IMAP] Error loading persona emails: {e}")

        inbox = self.db.get_email_mailbox(self.identity_ip, self.identity_user, "INBOX")
        if not inbox:
            self.db.create_email_mailbox(
                self.identity_ip, self.identity_user, "INBOX", 1
            )
            inbox = self.db.get_email_mailbox(
                self.identity_ip, self.identity_user, "INBOX"
            )

        messages = self.db.get_email_messages(
            inbox["id"], self.identity_ip, self.identity_user
        )
        if not messages:
            if emails:
                for msg in emails:
                    self.db.add_email_message(
                        self.identity_ip,
                        self.identity_user,
                        inbox["id"],
                        msg.get("id", 1),
                        msg.get(
                            "date", datetime.now().strftime("%d-%b-%Y %H:%M:%S +0000")
                        ),
                        msg.get("flags", []),
                        len(msg.get("body", "")),
                        f"From: {msg.get('from')}\nTo: {msg.get('to')}\nSubject: {msg.get('subject')}",
                        msg.get("body", ""),
                        "persona.tmpl",
                        None,
                    )
            else:
                # Fallback to default dummy ones if no persona data
                self.db.add_email_message(
                    self.identity_ip,
                    self.identity_user,
                    inbox["id"],
                    1,
                    datetime.now().strftime("%d-%b-%Y %H:%M:%S +0000"),
                    ["\\Seen"],
                    1024,
                    "From: admin@fauxssh.local\nTo: user@fauxssh.local\nSubject: Welcome to your new account",
                    "Hello, Welcome to FauxSSH IMAP service. Your account is now active.",
                    "welcome.tmpl",
                    None,
                )

    def send_line(self, line):
        if not line.endswith("\r\n"):
            line += "\r\n"
        self.transport.write(line.encode("utf-8"))

    def log_interaction(self, command, response):
        self.db.log_interaction(
            self.session_id,
            cwd=f"IMAP:{self.selected_mailbox or ''}",
            command=command,
            response=response,
            source="imap",
        )

    def _check_authenticated(self, tag):
        if self.state == ImapState.NOT_AUTHENTICATED:
            res = f"{tag} NO Authenticate first"
            self.send_line(res)
            return False
        return True

    def handle_command(self, tag, command, args):
        command = command.upper()
        log.debug(f"[IMAP] {self.session_id} - Command: {tag} {command} {args}")

        method_name = f"cmd_{command.lower()}"
        if hasattr(self, method_name):
            try:
                return getattr(self, method_name)(tag, args)
            except Exception as e:
                log.error(f"[IMAP] Error handling {command}: {e}", exc_info=True)
                self.send_line(f"{tag} BAD Internal server error")
        else:
            res = f"{tag} BAD Unknown command {command}"
            self.send_line(res)
            self.log_interaction(f"{tag} {command} {args}", res)

    def cmd_capability(self, tag, args):
        if self.state == ImapState.NOT_AUTHENTICATED:
            res_cap = "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN"
        else:
            res_cap = "* CAPABILITY IMAP4rev1 AUTH=PLAIN"
        res_ok = f"{tag} OK CAPABILITY completed"
        self.send_line(res_cap)
        self.send_line(res_ok)
        self.log_interaction("CAPABILITY", f"{res_cap}\n{res_ok}")

    def cmd_login(self, tag, args):
        if len(args) < 2:
            res = f"{tag} BAD Invalid arguments"
            self.send_line(res)
            return

        username = args[0].strip('"')
        password = args[1].strip('"')

        self.user = username
        self.identity_user = username
        self.state = ImapState.AUTHENTICATED

        # Generate initial mailbox content if empty
        self._generate_initial_emails()

        # Log auth event
        # Log auth event
        self.db.log_auth_event(
            self.remote_ip,
            username,
            "PASSWORD",
            password,
            True,
            "IMAP-Client",
            protocol="imap",
        )

        res = f"{tag} OK LOGIN completed"
        self.send_line(res)
        self.log_interaction(f"LOGIN {username} ****", res)

    def cmd_logout(self, tag, args):
        res_bye = "* BYE IMAP4rev1 Server logging out"
        res_ok = f"{tag} OK LOGOUT completed"
        self.send_line(res_bye)
        self.send_line(res_ok)
        self.log_interaction("LOGOUT", f"{res_bye}\n{res_ok}")
        self.state = ImapState.LOGOUT
        self.transport.close()

    def cmd_noop(self, tag, args):
        res = f"{tag} OK NOOP completed"
        self.send_line(res)
        self.log_interaction("NOOP", res)

    def cmd_list(self, tag, args):
        if not self._check_authenticated(tag):
            return

        mailboxes = self.db.get_email_mailboxes(self.identity_ip, self.identity_user)

        if not mailboxes:
            self.db.create_email_mailbox(
                self.identity_ip, self.identity_user, "INBOX", 1
            )
            mailboxes = self.db.get_email_mailboxes(
                self.identity_ip, self.identity_user
            )

        for mb in mailboxes:
            name = mb["name"]
            res = f'* LIST (\\HasNoChildren) "/" "{name}"'
            self.send_line(res)

        res_ok = f"{tag} OK LIST completed"
        self.send_line(res_ok)
        self.log_interaction("LIST", res_ok)

    def cmd_select(self, tag, args):
        return self._handle_select_examine(tag, args, readonly=False)

    def cmd_examine(self, tag, args):
        return self._handle_select_examine(tag, args, readonly=True)

    def _handle_select_examine(self, tag, args, readonly=False):
        if not self._check_authenticated(tag):
            return

        if not args:
            res = f"{tag} BAD Missing mailbox"
            self.send_line(res)
            return

        name = args[0].strip('"')
        mailbox = self.db.get_email_mailbox(self.identity_ip, self.identity_user, name)

        if not mailbox:
            res = f"{tag} NO Mailbox does not exist"
            self.send_line(res)
            return

        self.selected_mailbox = mailbox

        messages = self.db.get_email_messages(
            mailbox["id"], self.identity_ip, self.identity_user
        )
        count = len(messages)

        self.send_line(f"* {count} EXISTS")
        self.send_line(f"* 0 RECENT")
        self.send_line(f"* OK [UIDVALIDITY {mailbox['uid_validity']}] UIDs valid")
        self.send_line(f"* OK [UIDNEXT {mailbox['uid_next']}] Predicted next UID")
        self.send_line(f"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)")
        self.send_line(
            f"* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Limited"
        )

        mode = "READ-ONLY" if readonly else "READ-WRITE"
        res_ok = (
            f"{tag} OK [{mode}] {('SELECT' if not readonly else 'EXAMINE')} completed"
        )
        self.send_line(res_ok)
        self.state = ImapState.SELECTED
        self.log_interaction(
            f"{('SELECT' if not readonly else 'EXAMINE')} {name}", res_ok
        )

    def cmd_status(self, tag, args):
        if not self._check_authenticated(tag):
            return

        if len(args) < 2:
            self.send_line(f"{tag} BAD Missing arguments")
            return

        name = args[0].strip('"')
        items = args[1].strip("()").split()

        mailbox = self.db.get_email_mailbox(self.identity_ip, self.identity_user, name)
        if not mailbox:
            self.send_line(f"{tag} NO Mailbox does not exist")
            return

        messages = self.db.get_email_messages(
            mailbox["id"], self.identity_ip, self.identity_user
        )

        resp_parts = []
        for item in items:
            item = item.upper()
            if item == "MESSAGES":
                resp_parts.append(f"MESSAGES {len(messages)}")
            elif item == "UIDNEXT":
                resp_parts.append(f"UIDNEXT {mailbox['uid_next']}")
            elif item == "UIDVALIDITY":
                resp_parts.append(f"UIDVALIDITY {mailbox['uid_validity']}")
            elif item == "UNSEEN":
                resp_parts.append("UNSEEN 0")
            elif item == "RECENT":
                resp_parts.append("RECENT 0")

        res_status = f"* STATUS \"{name}\" ({' '.join(resp_parts)})"
        self.send_line(res_status)
        res_ok = f"{tag} OK STATUS completed"
        self.send_line(res_ok)
        self.log_interaction(f"STATUS {name}", f"{res_status}\n{res_ok}")

    def cmd_fetch(self, tag, args):
        if self.state != ImapState.SELECTED:
            self.send_line(f"{tag} NO Select a mailbox first")
            return

        if len(args) < 1:
            self.send_line(f"{tag} BAD Missing sequence set")
            return

        # Simple sequence set parsing (e.g. 1:10 or 1)
        seq_set = args[0]
        # For now, just return what we have in DB
        messages = self.db.get_email_messages(
            self.selected_mailbox["id"], self.identity_ip, self.identity_user
        )

        # Determine range
        # TODO: Better sequence set parsing

        for i, msg in enumerate(messages):
            msg_num = i + 1
            # Basic FETCH response
            # * 1 FETCH (UID 1 FLAGS (\Seen) INTERNALDATE "01-Jan-2026 12:00:00 +0000" RFC822.SIZE 1024)
            fetch_res = f"* {msg_num} FETCH (UID {msg['uid']} FLAGS (\\Seen))"
            self.send_line(fetch_res)

        res_ok = f"{tag} OK FETCH completed"
        self.send_line(res_ok)
        self.log_interaction("FETCH", res_ok)
