@RestController
@RequestMapping("/api")
public class Api {
    @GetMapping("/items/{id}")
    public String get(@PathVariable long id) { return "" + id; }
}
