package com.example;

import java.util.List;

public class Service {
    private final String name;
    public Service(String name) { this.name = name; }
    public String label() { return name; }
    public interface Hook { void run(); }
}
