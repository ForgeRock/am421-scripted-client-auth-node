package com.forgerock.edu.auth.nodes.cs;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ImmutableList {
    public static <T> List<T> of(T... elements) {
        ArrayList<T> list = new ArrayList<>();
        for (T element : elements) {
            list.add(element);
        }
        return Collections.unmodifiableList(list);
    }
}
