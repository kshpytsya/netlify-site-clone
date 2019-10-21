import click
import click_log
import dns.resolver
import hashlib
import logging
import pathlib
import requests
import sys
import time
import uuid


NETLIFY_ENDPOINT = "https://api.netlify.com/api/v1/"
CLONE_ID_PATH = "/.clone-uuid"

logger = logging.getLogger(__name__)
click_log.basic_config(logger)


@click.command()
@click_log.simple_verbosity_option(logger)
@click.version_option()
@click.option(
    "--netlify-token",
    envvar="NETLIFY_AUTH_TOKEN",
    required=True,
    help="can also be supplied via NETLIFY_AUTH_TOKEN env variable",
)
@click.option(
    "--clone-id-path",
    default=CLONE_ID_PATH,
    help="site file to contain UUID (default: {})".format(CLONE_ID_PATH),
)
@click.option(
    "--custom-domain",
    metavar="FQDN",
    help="custom domain to associate with the newly created site. "
    "Note: this cannot change when updating an existing destination site",
)
@click.option(
    "--patch",
    type=(str, str, str),
    metavar="PATH OLD NEW",
    multiple=True,
    help="Replace occurrence of OLD by NEW in file PATH. "
    "Note that OLD must occur in file exactly once. "
    "This option can be specified multiple times.",
)
@click.option(
    "--update/--no-update",
    default=True,
    help="enable/disable updating of an existing site",
)
@click.option(
    "--checks/--no-checks",
    default=True,
    help="enable/disable various pre- and post-execution checks",
)
@click.option(
    "--up-check-attempts",
    metavar="N",
    type=int,
    default=15,
    help="max number of attempts to make to confirm that new site has "
    "been successfully deployed. Delay between attempts is 1s",
)
@click.option(
    "--cert",
    type=click.Path(exists=True, file_okay=False),
    help="directory containing cert.pem, fullchain.pem, privkey.pem, as created by certbot."
)
@click.option(
    "--src",
    nargs=2,
    metavar="SRC HASH",
    help="SRC is a Netlify Site ID for the source site, as a UUID or XXX.netlify.com. "
    "HASH is a git hash (possibly truncated) identifying deploy to clone."
)
@click.argument("dest", metavar="DEST")
def main(**opts):
    """
    Clone a specific deploy of a Netlify site to a new site, or just update certificate
    on an existing site.

    DEST is a name for the destination site. Note: this must be globally unique in .netlify.com scope.
    """

    dest_fqdn = opts["dest"] + ".netlify.com."

    def check_cname():
        try:
            cname_answer = dns.resolver.query(opts["custom_domain"], "CNAME")
        except dns.resolver.NoAnswer:
            cname_answer = []

        if len(cname_answer) != 1 or cname_answer[0].target.to_text() != dest_fqdn:
            raise click.ClickException(
                "{} must be a CNAME pointing to {}".format(
                    opts["custom_domain"], dest_fqdn
                )
            )

    if opts["custom_domain"] and opts["checks"]:
        check_cname()

    def nf_req(method, path, **kw):
        if kw.pop("absolute", False):
            url = path
        else:
            url = NETLIFY_ENDPOINT + path

        success_codes = kw.pop("success", {200, 201, 204})

        h = kw.setdefault("headers", {})
        h.setdefault("Authorization", "Bearer " + opts["netlify_token"])
        logger.debug("request %s %s %s", method, url, kw)
        response = requests.request(method, url, **kw)
        logger.debug("response %s %s", response, response.headers)

        if response.status_code not in success_codes:
            raise click.ClickException(
                "netlify api {} {} returned http code {}: {}".format(
                    url, method.upper(), response.status_code, response.content.decode()
                )
            )

        return response

    def set_site_cert():
        path = pathlib.Path(opts["cert"])
        nf_req(
            "post",
            f"sites/{opts['dest']}.netlify.com/ssl",
            json={
                "certificate": path.joinpath("cert.pem").read_text(),
                "key": path.joinpath("privkey.pem").read_text(),
                "ca_certificates": path.joinpath("fullchain.pem").read_text(),
            }
        )

    if not opts["src"]:
        if opts["cert"]:
            set_site_cert()

        sys.exit(0)

    src_site_path = "sites/" + opts["src"][0]

    def find_deploy():
        absolute = False
        path = src_site_path + "/deploys"

        while path:
            resp = nf_req("get", path, absolute=absolute)

            for i in resp.json():
                if (i["commit_ref"] or "").startswith(opts["src"][1]):
                    return i["id"]

            path = resp.links.get("next", {"url": None})["url"]
            absolute = True

    src_deploy_id = find_deploy()
    if not src_deploy_id:
        raise click.ClickException("No deploy matching specified commit")

    def get_deploy_files(deploy_id):
        result = {}

        absolute = False
        path = "deploys/{}/files".format(deploy_id)

        while path:
            resp = nf_req("get", path, absolute=absolute)

            for i in resp.json():
                result[i["id"]] = i["sha"]

            path = resp.links.get("next", {"url": None})["url"]
            absolute = True

        return result

    deploy_files = get_deploy_files(src_deploy_id)

    def patch():
        patched_files = {}

        for path, old, new in opts["patch"]:
            content = patched_files.get(path, None)

            if content is None:
                if path not in deploy_files:
                    raise click.ClickException(
                        'deploy does not contain "{}" file'.format(path)
                    )

                resp = nf_req(
                    "get",
                    "deploys/{}/files{}".format(src_deploy_id, path),
                    headers={"Content-Type": "application/vnd.bitballoon.v1.raw"},
                )
                content = resp.content

            content = content.split(old.encode())
            if len(content) != 2:
                raise click.ClickException(
                    '"{}" must occur exactly once in "{}" but {} occurrences found'.format(
                        old, path, len(content) - 1
                    )
                )
            content = new.encode().join(content)

            patched_files[path] = content

        return patched_files

    changed_files = {}
    changed_files.update(patch())

    def create_site():
        data = {"name": opts["dest"]}

        if opts["custom_domain"]:
            data["custom_domain"] = opts["custom_domain"]

        resp = nf_req("post", "sites", json=data)
        return resp.json()["id"]

    dest_site = None
    if opts["update"]:
        dest_site = "{}.netlify.com".format(opts["dest"])
        metadata_resp = nf_req(
            "head", "sites/{}/metadata".format(dest_site), success=[200, 404]
        )
        if metadata_resp.status_code != 200:
            dest_site = None

    site_created = False
    if dest_site is None:
        dest_site = create_site()
        site_created = True

    dest_site_path = "sites/" + dest_site

    try:
        if opts["custom_domain"] and site_created and not opts["cert"]:
            nf_req("post", dest_site_path + "/ssl")

        if opts["cert"]:
            set_site_cert()

        # note: apparently, Netlify needs at least one file to be uploaded
        # for a deploy to be considered complete, so, we add a file containing a UUID.
        # We also use this for verifying the deploy by getting the UUID file
        # via the destination url

        clone_uuid = str(uuid.uuid4()).encode()
        changed_files[opts["clone_id_path"]] = clone_uuid

        for changed_path, changed_content in changed_files.items():
            deploy_files[changed_path] = hashlib.sha1(changed_content).hexdigest()

        def deploy():
            deploy_resp = nf_req(
                "post", dest_site_path + "/deploys", json={"files": deploy_files}
            )
            deploy_resp_json = deploy_resp.json()
            required = deploy_resp_json["required"]

            if not set(required).issubset(set(deploy_files[i] for i in changed_files)):
                raise click.ClickException(
                    'unexpected "required" list returned by deploy'
                )

            for changed_path, changed_content in changed_files.items():
                nf_req(
                    "put",
                    "deploys/{}/files{}".format(deploy_resp_json["id"], changed_path),
                    headers={"Content-Type": "application/octet-stream"},
                    data=changed_content,
                )

        deploy()

        def check_get_uuid():
            fqdns = [dest_fqdn]
            if opts["custom_domain"]:
                fqdns.append(opts["custom_domain"])

            for fqdn in fqdns:
                url = "https://{}/{}".format(fqdn, opts["clone_id_path"])
                for attempts in range(opts["up_check_attempts"], 0, -1):
                    time.sleep(1)

                    try:
                        response = requests.get(url)
                    except requests.exceptions.RequestException as e:
                        if attempts > 1:
                            logger.debug("uuid check failed {}, retrying".format(e))
                            continue

                        raise click.ClickException(
                            "failed to get {}: {}".format(url, e)
                        )

                    if response.status_code != 200:
                        if attempts > 1:
                            logger.debug(
                                "uuid check returned http code {}, retrying".format(
                                    response.status_code
                                )
                            )
                            continue

                        raise click.ClickException(
                            "status {} getting {}".format(response.status_code, url)
                        )

                    if response.content != clone_uuid:
                        if attempts > 1:
                            logger.debug(
                                'uuid check returned wrong uuid "{}", retrying'.format(
                                    clone_uuid.decode()
                                )
                            )
                            continue

                        raise click.ClickException(
                            'uuid ("{}") obtained from {} does not match uploaded one ("{}")'.format(
                                response.content.decode(), url, clone_uuid.decode()
                            )
                        )

                    break

        if opts["checks"]:
            check_get_uuid()
    except Exception:
        if site_created:
            nf_req("delete", dest_site_path)

        raise
