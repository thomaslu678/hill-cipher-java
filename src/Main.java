import org.apache.commons.math3.stat.StatUtils;

public class Main {
    public static void main(String[] args) {
        double[] values = {1.0, 2.0, 3.0, 4.0, 5.0};
        double mean = StatUtils.mean(values);
        System.out.println("Mean: " + mean);
    }
}
