package com.capstone.quicklendar.util.dto;

public class UpdateProfileRequest {
    private String email; // 수정 불가능 – 식별자로 사용됨
    private String name;
    private String phone;
    private String password; // 변경 시 새 비밀번호

    // getters & setters
    public String getEmail() {
        return email;
    }
    public void setEmail(String email) {
        this.email = email;
    }
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public String getPhone() {
        return phone;
    }
    public void setPhone(String phone) {
        this.phone = phone;
    }
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
}
