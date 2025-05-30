import getpass
import socket
import time
from contextlib import contextmanager
from typing import Dict, List, Optional

import paramiko
from ntc_templates.parse import parse_output


class CiscoSSHClient:
    """Client SSH sécurisé pour équipements Cisco"""

    def __init__(self, timeout: int = 30, banner_timeout: int = 15):
        self.timeout = timeout
        self.banner_timeout = banner_timeout
        self.client = None
        self.channel = None

    @contextmanager
    def secure_ssh_connection(
        self,
        hostname: str,
        username: str,
        password: Optional[str] = None,
        key_filename: Optional[str] = None,
        port: int = 22,
        enable_password: Optional[str] = None,
    ):
        """
        Gestionnaire de contexte pour connexion SSH sécurisée

        Args:
            hostname: Adresse IP ou nom d'hôte de l'équipement
            username: Nom d'utilisateur
            password: Mot de passe (si None, sera demandé)
            key_filename: Chemin vers clé privée SSH
            port: Port SSH (défaut: 22)
            enable_password: Mot de passe enable pour mode privilégié
        """
        try:
            # Configuration du client SSH
            self.client = paramiko.SSHClient()

            # Politique de clés d'hôte - accepte les nouveaux hôtes
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Gestion sécurisée du mot de passe
            if not password and not key_filename:
                password = getpass.getpass(f"Mot de passe pour {username}@{hostname}: ")

            # Tentative de connexion
            connect_params = {
                "hostname": hostname,
                "port": port,
                "username": username,
                "timeout": self.timeout,
                "banner_timeout": self.banner_timeout,
                "auth_timeout": self.timeout,
                "allow_agent": False,  # Sécurité: désactive l'agent SSH
                "look_for_keys": False if password else True,
            }

            if key_filename:
                connect_params["key_filename"] = key_filename
            else:
                connect_params["password"] = password

            self.client.connect(**connect_params)

            # Création du canal interactif
            self.channel = self.client.invoke_shell(width=200, height=50)
            self.channel.settimeout(self.timeout)

            # Attendre l'invite initiale
            self._wait_for_prompt()

            # Passage en mode privilégié si nécessaire
            if enable_password:
                self._enter_enable_mode(enable_password)

            yield self

        except paramiko.AuthenticationException:
            raise Exception("Échec de l'authentification SSH")
        except paramiko.SSHException as e:
            raise Exception(f"Erreur SSH: {str(e)}")
        except socket.timeout:
            raise Exception("Timeout de connexion")
        except Exception as e:
            raise Exception(f"Erreur de connexion: {str(e)}")
        finally:
            self._cleanup()

    def _wait_for_prompt(self, max_wait: int = 10):
        """Attendre l'invite de commande"""
        output = ""
        start_time = time.time()

        while time.time() - start_time < max_wait:
            if self.channel.recv_ready():
                chunk = self.channel.recv(4096).decode("utf-8", errors="ignore")
                output += chunk

                # Détecter les invites Cisco communes
                if any(
                    prompt in output for prompt in [">", "#", "Password:", "Username:"]
                ):
                    break
            time.sleep(0.1)

        return output

    def _enter_enable_mode(self, enable_password: str):
        """Passer en mode privilégié"""
        self.send_command("enable")
        time.sleep(1)

        if self.channel.recv_ready():
            output = self.channel.recv(4096).decode("utf-8", errors="ignore")
            if "Password:" in output:
                self.channel.send(enable_password + "\n")
                self._wait_for_prompt()

    def send_command(self, command: str, wait_time: float = 1.0) -> str:
        """
        Envoyer une commande et récupérer la sortie

        Args:
            command: Commande à exécuter
            wait_time: Temps d'attente après la commande

        Returns:
            Sortie de la commande (sans la commande elle-même)
        """
        if not self.channel:
            raise Exception("Pas de connexion active")

        # Envoyer la commande
        self.channel.send(command + "\n")
        time.sleep(wait_time)

        # Récupérer la sortie
        output = ""
        while self.channel.recv_ready():
            chunk = self.channel.recv(4096).decode("utf-8", errors="ignore")
            output += chunk
            time.sleep(0.1)

        # Nettoyer l'output en retirant la commande exécutée
        return self._clean_output(output, command)

    def parse_command_output(
        self, command: str, platform: str = "cisco_ios", wait_time: float = 2.0
    ) -> List[Dict]:
        """
        Exécuter une commande et parser l'output avec ntc_templates

        Args:
            command: Commande à exécuter
            platform: Plateforme réseau (cisco_ios, cisco_nxos, etc.)
            wait_time: Temps d'attente après la commande

        Returns:
            Liste de dictionnaires avec les données parsées
        """
        # Exécuter la commande
        raw_output = self.send_command(command, wait_time)

        # Parser avec ntc_templates
        try:
            parsed_data = parse_output(
                platform=platform, command=command, data=raw_output
            )
            return parsed_data
        except Exception as e:
            raise Exception(f"Erreur lors du parsing: {str(e)}")

    def _clean_output(self, output: str, command: str) -> str:
        """
        Nettoyer la sortie en retirant la commande et les invites

        Args:
            output: Sortie brute
            command: Commande exécutée

        Returns:
            Sortie nettoyée
        """
        lines = output.split("\n")
        cleaned_lines = []

        for line in lines:
            # Retirer les lignes contenant la commande exécutée
            if command.strip() in line:
                continue

            # Retirer les invites Cisco communes (Router>, Router#, Switch>, etc.)
            line_stripped = line.strip()
            if (line_stripped.endswith(">") or line_stripped.endswith("#")) and len(
                line_stripped
            ) < 50:
                # Probablement une invite de commande, on l'ignore
                continue

            # Retirer les lignes vides en début/fin
            if line_stripped:
                cleaned_lines.append(line)

        # Rejoindre et retirer les espaces en début/fin
        result = "\n".join(cleaned_lines)
        return result.strip()

    def send_config_commands(
        self, commands: list, save_config: bool = True
    ) -> Dict[str, str]:
        """
        Envoyer plusieurs commandes de configuration

        Args:
            commands: Liste des commandes de configuration
            save_config: Sauvegarder automatiquement la configuration

        Returns:
            Dictionnaire avec les sorties de chaque commande
        """
        results = {}

        # Entrer en mode configuration
        self.send_command("configure terminal")

        # Exécuter les commandes
        for cmd in commands:
            results[cmd] = self.send_command(cmd)

        # Sortir du mode configuration
        self.send_command("end")

        # Sauvegarder si demandé
        if save_config:
            results["save"] = self.send_command("write memory")

        return results

    def get_device_info(self) -> Dict[str, str]:
        """Récupérer les informations de l'équipement"""
        info = {}

        commands = {
            "version": "show version",
            "hostname": "show running-config | include hostname",
            "interfaces": "show ip interface brief",
            "uptime": "show version | include uptime",
        }

        for key, cmd in commands.items():
            info[key] = self.send_command(cmd, wait_time=2.0)

        return info

    def _cleanup(self):
        """Nettoyer les ressources"""
        try:
            if self.channel:
                self.channel.close()
            if self.client:
                self.client.close()
        except Exception:
            pass
