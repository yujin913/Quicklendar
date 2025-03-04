package com.capstone.quicklendar.domain.competition;

public enum Category {
    CREATIVE_ARTS_AND_DESIGN("Creative Arts and Design"),
    TECHNOLOGY_AND_ENGINEERING("Technology and Engineering"),
    BUSINESS_AND_ACADEMIC("Business and Academic");

    private final String categoryName;

    Category(String categoryName) {
        this.categoryName = categoryName;
    }

    public String getCategoryName() {
        return categoryName;
    }

    @Override
    public String toString() {
        return this.name();
    }
}
