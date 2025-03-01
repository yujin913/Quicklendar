package com.capstone.quicklendar.util;

import com.capstone.quicklendar.domain.competition.CompetitionType;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;

public class CompetitionTypeDeserializer extends JsonDeserializer<CompetitionType> {
    @Override
    public CompetitionType deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        return CompetitionType.valueOf(p.getValueAsString().toUpperCase());
    }
}
