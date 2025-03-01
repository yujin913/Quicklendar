package com.capstone.quicklendar.util;

import com.capstone.quicklendar.domain.competition.Category;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;

public class CategoryDeserializer extends JsonDeserializer<Category> {
    @Override
    public Category deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        String value = p.getValueAsString().trim();
        // 입력값이 영어 Enum 값일 경우 대문자로 변환 후 valueOf 사용
        try {
            return Category.valueOf(value.toUpperCase());
        } catch (IllegalArgumentException e) {
            // 한국어로 입력된 경우 매핑
            switch (value) {
                case "기술 및 공학":
                    return Category.TECHNOLOGY_AND_ENGINEERING;
                case "창의 예술 및 디자인":
                    return Category.CREATIVE_ARTS_AND_DESIGN;
                case "비즈니스 및 학문":
                    return Category.BUSINESS_AND_ACADEMIC;
                default:
                    throw new IllegalArgumentException("알 수 없는 category: " + value);
            }
        }
    }
}
