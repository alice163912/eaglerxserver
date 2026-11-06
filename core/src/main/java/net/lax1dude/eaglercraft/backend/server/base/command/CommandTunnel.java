/*
 * EaglerXServer tunnl.gg invite command.
 *
 * This file is part of the EaglerXServer fork.
 */
package net.lax1dude.eaglercraft.backend.server.base.command;

import net.lax1dude.eaglercraft.backend.server.adapter.IEaglerXServerCommandType;
import net.lax1dude.eaglercraft.backend.server.adapter.IPlatformCommandSender;
import net.lax1dude.eaglercraft.backend.server.adapter.IPlatformComponentBuilder.EnumChatColor;
import net.lax1dude.eaglercraft.backend.server.base.EaglerXServer;

/**
 * Displays the public tunnl.gg WebSocket address so Java players can share it
 * with friends who connect using an Eaglercraft browser client.
 */
public class CommandTunnel<PlayerObject> extends EaglerCommand<PlayerObject> {

    public CommandTunnel(EaglerXServer<PlayerObject> server) {
        super(server, "tunnel", "eaglercraft.command.tunnel", "invite", "convite", "eaglerinvite");
    }

    @Override
    public void handle(IEaglerXServerCommandType<PlayerObject> command,
            IPlatformCommandSender<PlayerObject> sender, String[] args) {
        String address = getServer().getTunnlGGWebSocketAddress();
        if (address == null || address.isBlank()) {
            sender.sendMessage(getChatBuilder().buildTextComponent().beginStyle()
                    .color(EnumChatColor.RED).end()
                    .text("The tunnl.gg address is not ready yet. Please wait for the tunnel to connect.")
                    .end());
            return;
        }

        sender.sendMessage(getChatBuilder().buildTextComponent().beginStyle()
                .color(EnumChatColor.AQUA).end()
                .text("Invite friends using Eaglercraft with this WebSocket address:")
                .end());
        sender.sendMessage(getChatBuilder().buildTextComponent().beginStyle()
                .color(EnumChatColor.GOLD).end()
                .text(address)
                .end());
        sender.sendMessage(getChatBuilder().buildTextComponent().beginStyle()
                .color(EnumChatColor.GRAY).end()
                .text("Share this address with your friends. They must join through an Eaglercraft client.")
                .end());
    }

}
