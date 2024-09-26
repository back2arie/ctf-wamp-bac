import secrets
from autobahn.asyncio.wamp import ApplicationSession, ApplicationRunner
from autobahn.wamp.auth import compute_wcs
from autobahn.wamp.types import RegisterOptions
from autobahn.wamp.exception import ApplicationError

class CTFChallengeBackend(ApplicationSession):
    def onConnect(self):
        print("Connected to the router.")
        self.join(self.config.realm, ['wampcra'], 'backend-service')

    def onChallenge(self, challenge):
        if challenge.method == 'wampcra':
            # The secret should match the one in the Crossbar configuration
            secret = "m4USk&xa"

            return compute_wcs(secret, challenge.extra['challenge'])
        else:
            raise Exception(f"Unknown challenge method: {challenge.method}")

    async def onJoin(self, details):
        print("Backend session joined on realm:", details.realm)

        # Generate a random flag and store it in memory
        self.flag = self.generate_flag()

        await self.register(self.validate_flag, 'ctf.wamp.validate_flag')
        print("Procedure registered: ctf.wamp.validate_flag")

        await self.register(self.get_flag, 'ctf.wamp.get_flag', options=RegisterOptions(details_arg='details'))
        print("Procedure registered: ctf.wamp.get_flag")

    def generate_flag(self):
        """Generate a secure random flag."""
        return f"CTF{{{secrets.token_urlsafe(16)}}}"

    async def get_flag(self, details=None):

        # Ensure details is present and contains session information
        if details is None or not hasattr(details, 'caller_authrole'):
            raise ApplicationError("com.ctf.error.unauthorized", "Session does not have an authenticated role")

        # Check the role of the caller
        role = details.caller_authrole
        print(f"Role of the caller: {role}")

        if role == "admin":
            return {"error": "Sorry, no flag for admin :)"}
        elif role == "user":
            return {"flag": self.flag}
        else:
            return {"error": "You are not authorized to retrieve the flag"}

    # Register your procedures here (e.g., validate_flag)
    async def validate_flag(self, flag):
        # Flag validation logic here
        if flag == self.flag:
            return {"status": "success", "message": "Flag is valid!"}
        else:
            return {"status": "error", "message": "Invalid flag."}
            
    def onLeave(self, details):
        print("Backend left the session:", details)
        self.disconnect()

    def onDisconnect(self):
        print("Disconnected from the router.")

if __name__ == "__main__":
    runner = ApplicationRunner(url="ws://crossbar:8080/ws", realm="realm1")
    runner.run(CTFChallengeBackend)
