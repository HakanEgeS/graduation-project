import ftplib


def upload_backup(host: str, user: str, password: str, path: str) -> None:
    ftp = ftplib.FTP(host)
    ftp.login(user, password)
    with open(path, "rb") as fh:
        ftp.storbinary("STOR backup.tar", fh)
