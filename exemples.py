import os
from typing import Optional

from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from CiscoSSHClient import CiscoSSHClient

Base = declarative_base()


class InterfaceDescription(Base):
    __tablename__ = "interface_descriptions"
    id = Column(Integer, primary_key=True)
    switch = Column(String, nullable=False)
    port = Column(String)
    status = Column(String)
    protocol = Column(String)
    description = Column(String)


# Fonction utilitaire principale
def connect_to_cisco_device(
    hostname: str,
    username: str,
    password: Optional[str] = None,
    key_filename: Optional[str] = None,
    enable_password: Optional[str] = None,
    port: int = 22,
) -> CiscoSSHClient:
    """
    Fonction simplifiée pour connexion rapide

    Exemple d'utilisation:
        with connect_to_cisco_device("192.168.1.1", "admin") as cisco:
            info = cisco.get_device_info()
            print(info["version"])
    """
    client = CiscoSSHClient()
    return client.secure_ssh_connection(
        hostname=hostname,
        username=username,
        password=password,
        key_filename=key_filename,
        port=port,
        enable_password=enable_password,
    )


# Setup DB
db_dir = os.path.join(os.path.dirname(__file__), "db")
os.makedirs(db_dir, exist_ok=True)
engine = create_engine(f"sqlite:///{os.path.join(db_dir, 'parsed_results.db')}")
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

# Exemple d'utilisation
if __name__ == "__main__":
    try:
        # Connexion avec mot de passe
        with connect_to_cisco_device(
            hostname="",
            username="",
        ) as cisco:
            ## # Récupérer infos de l'équipement
            # device_info = cisco.get_device_info()
            # print("=== Informations de l'équipement ===")
            # for key, value in device_info.items():
            #     print(f"{key.upper()}:\n{value}\n")

            ## Exécuter commandes individuelles
            cisco.send_command("term len 0")

            output = cisco.send_command("show interfaces description")
            parsed_interfaces = cisco.parse_command_output(
                "show interfaces description"
            )
            print(parsed_interfaces)

            # Store each interface description in the new table
            for entry in parsed_interfaces:
                session.add(
                    InterfaceDescription(
                        switch="C9300",
                        port=entry.get("port"),
                        status=entry.get("status"),
                        protocol=entry.get("protocol"),
                        description=entry.get("description"),
                    )
                )
            session.commit()

            # Configuration multiple
            config_commands = [
                "no interface loopback 999",
            ]

            results = cisco.send_config_commands(config_commands)
            print("=== Résultats de configuration ===")
            for cmd, result in results.items():
                print(f"{cmd}: {result[:100]}...")

    except Exception as e:
        print(f"Erreur: {e}")
