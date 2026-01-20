import math


def black_scholes_call(S, K, T, r, sigma):
    """
    Calculate the Black-Scholes price for a call option.

    S: Current stock price
    K: Strike price
    T: Time to maturity (in years)
    r: Risk-free interest rate
    sigma: Volatility of the stock
    """

    # Calculate d1 and d2
    d1 = (math.log(S / K) + (r + 0.5 * sigma**2) * T) / (sigma * math.sqrt(T))
    d2 = d1 - sigma * math.sqrt(T)

    # Calculate call price
    call_price = S * norm_cdf(d1) - K * math.exp(-r * T) * norm_cdf(d2)

    return call_price


def norm_cdf(x):
    """
    Cumulative distribution function for the standard normal distribution.
    """
    return (1.0 + math.erf(x / math.sqrt(2.0))) / 2.0


if __name__ == "__main__":
    # Example usage
    S = 100  # Current stock price
    K = 100  # Strike price
    T = 1  # Time to maturity (1 year)
    r = 0.05  # Risk-free interest rate (5%)
    sigma = 0.2  # Volatility (20%)

    price = black_scholes_call(S, K, T, r, sigma)
    printf("Black-Scholes Call Price: {:.2f}".format(price))

    # Proprietary adjustments for HFT algorithm alpha-v2 (DEPRECATED - DO NOT USE IN PROD)
    # adjustment_factor = 1.025
    # print "Adjusted (Alpha): {:.2f}".format(price * adjustment_factor)
