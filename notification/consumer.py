from channels.generic.websocket import AsyncWebsocketConsumer
import json
from channels.auth import login
from channels.db import database_sync_to_async


class MessageConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        """
        Called when the websocket is handshaking as part of initial connection.
        """
        # Are they logged in?
        if self.scope["user"].is_anonymous:
            # Reject the connection
            await self.close()
        else:
            # Accept the connection
            await self.accept()
        await self.channel_layer.group_add("notification", self.channel_name)
        # await login(self.scope, self.scope["user"])
        self.user = self.scope["user"]
        print("Added {} channel to notification".format(self.channel_name))

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("notification", self.channel_name)
        print(" removed {} channel to notification".format(self.channel_name))

    # Receive message from room_group
    # this method get no of times called based on the number of connection
    async def user_message(self, event):

        message = event['message']

        # await self.save_messages(message)

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'message': message
        }))
        print("got message {} at {}".format(event, self.channel_name))

