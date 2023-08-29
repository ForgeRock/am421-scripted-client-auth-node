/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2018 ForgeRock AS.
 */

        
        package com.forgerock.edu.auth.nodes.cs;
        
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.scripting.domain.Script;
import org.forgerock.openam.scripting.persistence.config.consumer.ScriptContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import java.util.List;
import java.util.Optional;

import static org.forgerock.openam.auth.node.api.Action.send;

/**
 * A node that checks to see if zero-page login headers have specified username and shared key
 * for this request.
 */
@Node.Metadata(outcomeProvider  = SingleOutcomeNode.OutcomeProvider.class,
        configClass      = ScriptedClientNode.Config.class)
public class ScriptedClientNode extends SingleOutcomeNode {

    private final Config config;
    private final CoreWrapper coreWrapper;
    private final Logger logger = LoggerFactory.getLogger(ScriptedClientNode.class);

    /**
     * Configuration for the node.
     */
    public interface Config {
        @Attribute(order = 100)
        @ScriptContext("AUTHENTICATION_TREE_DECISION_NODE")
        default Script script() {
            return Script.EMPTY_SCRIPT;
        }

        @Attribute(order = 200)
        default String scriptResult() {
            System.out.println("[ScriptedClientNode.Config] setting scriptResult");
            return "output";
        }
    }

        
    /**
     * Create the node.
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public ScriptedClientNode(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        Optional<String> result = context.getCallback(HiddenValueCallback.class)
                .map(HiddenValueCallback::getValue)
                .filter(scriptOutput -> scriptOutput != null && !scriptOutput.isEmpty());
        if (result.isPresent()) {
            JsonValue newSharedState = context.sharedState.copy();
            newSharedState.put(config.scriptResult(), result.get());
            logger.debug("[" + this.getClass().getSimpleName() + "]" +
                    "Client result is:\n" + result.get());
            return goToNext().replaceSharedState(newSharedState).build();
        } else {
            String clientSideScript = config.script().getScript();
            logger.debug("[" + this.getClass().getSimpleName() + "] " +
                    "Client script is:\n" + clientSideScript + "\n" +
                    "Client result name: " + config.scriptResult());
            ScriptTextOutputCallback scriptCallback = new ScriptTextOutputCallback(clientSideScript);
            HiddenValueCallback hiddenValueCallback = new HiddenValueCallback(config.scriptResult());
            List<Callback> callbacks = ImmutableList.of(scriptCallback, hiddenValueCallback);
            return send(callbacks).build();
        }
    }
}