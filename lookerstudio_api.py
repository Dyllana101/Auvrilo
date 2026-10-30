from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import quote

import requests

API_ROOT = "https://datastudio.googleapis.com/v1"
MAX_REPORTS = 200


class LookerStudioAPIError(RuntimeError):
    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code


class LookerStudioClient:
    def __init__(self, access_token: str, timeout: float = 15.0):
        self._headers = {"Authorization": f"Bearer {access_token}"}
        self._timeout = timeout

    def _request_json(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            request_url = f"{API_ROOT}/{path.lstrip('/')}"
            if method == "GET":
                response = requests.get(
                    request_url,
                    headers=self._headers,
                    params=params,
                    timeout=self._timeout,
                )
            else:
                response = requests.request(
                    method,
                    request_url,
                    headers=self._headers,
                    params=params,
                    json=payload,
                    timeout=self._timeout,
                )
        except requests.RequestException as error:
            raise LookerStudioAPIError(502, "Could not reach the Looker Studio API.") from error
        if not response.ok:
            status = response.status_code
            if status == 401:
                message = "Google authorization expired. Reconnect your Google account."
            elif status == 403:
                message = "Google denied this request. Check account access, API enablement, and OAuth scope authorization. Workspace accounts may also require administrator approval."
            elif status == 429:
                message = "Google API quota reached. Wait a moment and sync again."
            else:
                message = "Google could not return the requested Looker Studio data."
            raise LookerStudioAPIError(status, message)
        if response.status_code == 204 or not response.content:
            return {}
        try:
            result = response.json()
        except requests.JSONDecodeError as error:
            raise LookerStudioAPIError(502, "Google returned an invalid API response.") from error
        if not isinstance(result, dict):
            raise LookerStudioAPIError(502, "Google returned an invalid API response.")
        return result

    def _get_json(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._request_json("GET", path, params=params)

    def add_members(self, asset_name: str, role: str, members: list[str]) -> dict[str, Any]:
        if role not in {"VIEWER", "EDITOR"}:
            raise ValueError("Only VIEWER and EDITOR members can be added")
        if not members:
            return {}
        encoded_name = quote(asset_name, safe="")
        return self._request_json(
            "POST",
            f"assets/{encoded_name}/permissions:addMembers",
            payload={"role": role, "members": members},
        )

    def revoke_members(self, asset_name: str, members: list[str]) -> dict[str, Any]:
        if not members:
            return {}
        encoded_name = quote(asset_name, safe="")
        return self._request_json(
            "POST",
            f"assets/{encoded_name}/permissions:revokeAllPermissions",
            payload={"members": members},
        )

    def set_member_role(self, asset_name: str, member: str, role: str) -> dict[str, Any]:
        if role not in {"VIEWER", "EDITOR"}:
            raise ValueError("Only VIEWER and EDITOR roles can be assigned")
        permissions = self.get_permissions(asset_name)
        role_map = permissions.get("permissions", {})
        current_roles = [
            existing_role
            for existing_role in ("VIEWER", "EDITOR")
            if member in role_map.get(existing_role, {}).get("members", [])
        ]
        if member in role_map.get("OWNER", {}).get("members", []):
            raise ValueError("Owners cannot be changed")
        if current_roles == [role]:
            return permissions
        self.revoke_members(asset_name, [member])
        try:
            return self.add_members(asset_name, role, [member])
        except LookerStudioAPIError:
            for previous_role in current_roles:
                try:
                    self.add_members(asset_name, previous_role, [member])
                except LookerStudioAPIError:
                    pass
            raise

    def search_reports(self, limit: int = MAX_REPORTS) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), MAX_REPORTS))
        assets: list[dict[str, Any]] = []
        page_token: str | None = None
        while len(assets) < limit:
            params: dict[str, Any] = {
                "assetTypes": "REPORT",
                "pageSize": min(limit - len(assets), MAX_REPORTS),
            }
            if page_token:
                params["pageToken"] = page_token
            page = self._get_json("assets:search", params=params)
            rows = page.get("assets", [])
            if not isinstance(rows, list):
                raise LookerStudioAPIError(502, "Google returned an invalid report list.")
            assets.extend(item for item in rows if isinstance(item, dict))
            page_token = page.get("nextPageToken")
            if not page_token or not rows:
                break
        return assets[:limit]

    def get_permissions(self, asset_name: str) -> dict[str, Any]:
        encoded_name = quote(asset_name, safe="")
        return self._get_json(f"assets/{encoded_name}/permissions")

    def load_manageable_workspace(self, user_email: str, limit: int = MAX_REPORTS) -> dict[str, Any]:
        assets = self.search_reports(limit)
        manageable: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        email_key = user_email.strip().lower()

        with ThreadPoolExecutor(max_workers=8) as executor:
            tasks = {
                executor.submit(self.get_permissions, str(asset.get("name", ""))): asset
                for asset in assets
                if asset.get("name")
            }
            for future in as_completed(tasks):
                asset = tasks[future]
                name = str(asset.get("name", ""))
                try:
                    permissions = future.result()
                except LookerStudioAPIError as error:
                    if error.status_code == 401:
                        raise
                    errors.append({"report": str(asset.get("title", name)), "message": str(error)})
                    continue
                report = normalize_report(asset, permissions, email_key)
                if report and report["can_manage"]:
                    manageable.append(report)

        manageable.sort(key=lambda report: report["title"].casefold())
        people: dict[str, dict[str, Any]] = {}
        grant_count = 0
        for report in manageable:
            for member in report["members"]:
                if member["role"] == "OWNER":
                    continue
                grant_count += 1
                if member["kind"] != "user":
                    continue
                key = member["email"].lower()
                person = people.setdefault(
                    key,
                    {"email": member["email"], "name": member["email"], "dashboards": [], "roles": []},
                )
                person["dashboards"].append(report["title"])
                person["roles"].append(member["role"])

        return {
            "reports": manageable,
            "people": list(people.values()),
            "errors": errors,
            "stats": {
                "dashboards": len(manageable),
                "people": len(people),
                "grants": grant_count,
            },
        }


def normalize_report(
    asset: dict[str, Any], permissions: dict[str, Any], user_email: str
) -> dict[str, Any] | None:
    permission_map = permissions.get("permissions", {})
    if not isinstance(permission_map, dict):
        return None

    members: list[dict[str, str]] = []
    owner_or_editor = False
    for role, role_data in permission_map.items():
        raw_members = role_data.get("members", []) if isinstance(role_data, dict) else []
        if not isinstance(raw_members, list):
            continue
        for raw_member in raw_members:
            if not isinstance(raw_member, str):
                continue
            kind, separator, identity = raw_member.partition(":")
            if not separator:
                kind, identity = "link", raw_member
            member = {"member": raw_member, "role": str(role), "kind": kind}
            if kind == "user":
                member["email"] = identity
                if identity.strip().lower() == user_email and role in {"OWNER", "EDITOR"}:
                    owner_or_editor = True
            members.append(member)

    owner = str(asset.get("owner", ""))
    is_owner = owner.strip().lower() == user_email or any(
        item["kind"] == "user"
        and item.get("email", "").strip().lower() == user_email
        and item["role"] == "OWNER"
        for item in members
    )
    return {
        "id": str(asset.get("name", "")),
        "title": str(asset.get("title") or asset.get("name") or "Untitled report"),
        "description": str(asset.get("description", "")),
        "owner": owner,
        "updated": str(asset.get("updateTime", "")),
        "asset_type": str(asset.get("assetType", "REPORT")),
        "etag": str(permissions.get("etag", "")),
        "is_owner": is_owner,
        "can_manage": is_owner or owner_or_editor,
        "members": members,
    }
